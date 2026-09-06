"""OCP Virtualization (KubeVirt) provider implementation for CephVMNode."""

import base64
import ipaddress
import json
import os
import re
import subprocess
import tempfile
from copy import deepcopy
from pathlib import Path
from time import sleep
from typing import Any, Dict, List, Optional

import yaml
from kubernetes import client

from ceph.parallel import parallel
from ceph.waiter import WaitUntil
from utility.log import Log

from .exceptions import NodeDeleteFailure, NodeError

LOG = Log(__name__)
REPO_ROOT = Path(__file__).resolve().parent.parent

KUBEVIRT_GROUP = "kubevirt.io"
KUBEVIRT_VERSION = "v1"
CDI_GROUP = "cdi.kubevirt.io"
CDI_VERSION = "v1beta1"
KUBEVIRT_CLUSTER_INSTANCETYPE_KIND = "VirtualMachineClusterInstancetype"
INSTANCETYPE_GROUP = "instancetype.kubevirt.io"
INSTANCETYPE_VERSION = "v1beta1"
DEFAULT_OCPVIRT_PROFILE = "o1.large"
DEFAULT_OCPVIRT_ROOT_DISK_SIZE = "80Gi"

VM_POLL_INTERVAL = 10
# CSI attach (Trident/NFS) after CDI clone can exceed 20 minutes.
VM_POLL_TIMEOUT = 3600
IP_POLL_TIMEOUT = 600


def _sanitize_k8s_name(name: str) -> str:
    """Return a DNS-1123 compatible resource name (lowercase, hyphens)."""
    sanitized = name.lower().replace("_", "-").replace(".", "-")
    sanitized = re.sub(r"[^a-z0-9-]", "-", sanitized)
    sanitized = re.sub(r"-+", "-", sanitized).strip("-")
    return sanitized[:63].rstrip("-") or "ceph-vm"


def _disk_size_str(size_gib: Any, default: str = "40Gi") -> str:
    """Return a Kubernetes quantity string for disk size in GiB."""
    if size_gib is None or size_gib == "":
        return default
    if isinstance(size_gib, str) and size_gib.endswith(("Gi", "G", "Mi", "M", "Ti")):
        return size_gib
    try:
        return f"{int(size_gib)}Gi"
    except (TypeError, ValueError):
        return default


def _image_source(image_name: str) -> Dict[str, Any]:
    """
    Build a CDI DataVolume source from an inventory image-name.

    - datasource://<namespace>/<name> → sourceRef DataSource
    - http(s)://... → HTTP source
    - docker://... or registry path → registry source
    """
    if not image_name:
        raise NodeError("image-name is required for OCP Virt provisioning")

    image = image_name.strip()
    if image.startswith("datasource://"):
        rest = image[len("datasource://") :].strip("/")
        if not rest or "/" not in rest:
            raise NodeError(
                "datasource image-name must be datasource://<namespace>/<name>"
            )
        ns, name = rest.split("/", 1)
        if not ns or not name:
            raise NodeError(
                "datasource image-name must be datasource://<namespace>/<name>"
            )
        return {
            "_sourceRef": {
                "kind": "DataSource",
                "name": name,
                "namespace": ns,
            }
        }
    if image.startswith(("http://", "https://")):
        return {"http": {"url": image}}
    if image.startswith("docker://"):
        return {"registry": {"url": image}}
    # Bare image reference (e.g. quay.io/containerdisks/rhel:9)
    return {"registry": {"url": f"docker://{image}"}}


def get_k8s_clients(ocp_cred: dict):
    """
    Return (CustomObjectsApi, CoreV1Api) using bearer token auth from osp-cred.

    Required keys: ``server`` (from conf/ocpvirt) and ``token`` (from osp-cred).
    TLS verification is always enabled; set ``certificate_authority_data`` (base64
    CA from kubeconfig) or ``ssl_ca_cert`` (path) when the API uses a custom CA.

    Raises:
        NodeError: if required credentials are missing or invalid.
    """
    if not ocp_cred:
        raise NodeError("ocpvirt-credentials are required for --cloud ocpvirt")

    server = ocp_cred.get("server")
    token = ocp_cred.get("token")
    try:
        configuration = client.Configuration()
        configuration.host = server.rstrip("/")
        configuration.api_key["authorization"] = token
        configuration.api_key_prefix["authorization"] = "Bearer"
        configuration.verify_ssl = True
        if ocp_cred.get("ssl_ca_cert"):
            configuration.ssl_ca_cert = os.path.expanduser(ocp_cred["ssl_ca_cert"])
        elif ocp_cred.get("certificate_authority_data"):
            ca_pem = base64.b64decode(ocp_cred["certificate_authority_data"])
            ca_file = tempfile.NamedTemporaryFile(
                prefix="ocpvirt-ca-", suffix=".crt", delete=False
            )
            ca_file.write(ca_pem)
            ca_file.flush()
            ca_file.close()
            configuration.ssl_ca_cert = ca_file.name
        api_client = client.ApiClient(configuration)
        return (
            client.CustomObjectsApi(api_client),
            client.CoreV1Api(api_client),
        )
    except Exception as exc:
        raise NodeError(
            "Failed to authenticate to the OpenShift/Kubernetes API using "
            "token from osp-cred and server from conf/ocpvirt."
        ) from exc


def build_datavolume_spec(
    name: str,
    storage_class: str,
    size: str,
    source: Optional[Dict[str, Any]] = None,
    access_modes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a DataVolume template/spec body (used in dataVolumeTemplates)."""
    spec: Dict[str, Any] = {
        "storage": {
            "accessModes": access_modes or ["ReadWriteOnce"],
            "resources": {"requests": {"storage": size}},
            "storageClassName": storage_class,
        }
    }
    if source:
        if "_sourceRef" in source:
            spec["sourceRef"] = source["_sourceRef"]
        else:
            spec["source"] = source
    else:
        spec["source"] = {"blank": {}}
    return {
        "metadata": {"name": name},
        "spec": spec,
    }


def _cloudinit_secret_name(vm_name: str) -> str:
    """Secret name for VM cloud-init userdata (must stay DNS-1123 / <=63 chars)."""
    return f"{vm_name}-cloudinit"[:63].rstrip("-")


DEFAULT_UDN_SUBNET = ipaddress.ip_network("192.168.0.0/20")
OVERLAY_SUBNET = ipaddress.ip_network("172.16.0.0/12")


def _iface_ip_candidates(iface: dict) -> List[str]:
    """Unique IP strings from a VMI status.interfaces entry."""
    seen = set()
    out: List[str] = []
    for ip in [iface.get("ipAddress"), *(iface.get("ipAddresses") or [])]:
        if ip and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def udn_network(cred: Optional[dict] = None) -> ipaddress.IPv4Network:
    """Layer2 UDN CIDR from ocpvirt creds, else ``192.168.0.0/20``."""
    raw = None
    if cred:
        raw = cred.get("subnet") or cred.get("network_cidr")
    if raw:
        try:
            net = ipaddress.ip_network(str(raw), strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                return net
        except ValueError:
            pass
    return DEFAULT_UDN_SUBNET


def parse_ovn_secondary_cidr(
    annotation: str,
    namespace: str,
    network_name: str,
) -> Optional[str]:
    """Return ``ip/prefix`` for the secondary UDN from k8s.ovn.org/pod-networks."""
    if not annotation or not namespace or not network_name:
        return None
    try:
        data = json.loads(annotation)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    entry = data.get(f"{namespace}/{network_name}")
    if not isinstance(entry, dict):
        entry = None
        for value in data.values():
            if isinstance(value, dict) and str(value.get("role", "")).lower() == "secondary":
                entry = value
                break
    if not entry:
        return None
    cidr = entry.get("ip_address")
    if not cidr:
        addrs = entry.get("ip_addresses") or []
        cidr = addrs[0] if addrs else None
    if not cidr:
        return None
    text = str(cidr)
    host = text.split("/", 1)[0]
    if ":" in host:
        return None
    try:
        ipaddress.ip_interface(text)
    except ValueError:
        return None
    return text


def guest_udn_nmcli_script(mac: str, cidr: str) -> str:
    """Bash applied over SSH: put the OVN-assigned CIDR on the NIC with ``mac``."""
    mac = mac.strip().lower()
    if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise NodeError(f"invalid UDN MAC {mac!r}")
    iface = ipaddress.ip_interface(cidr)
    if not isinstance(iface, ipaddress.IPv4Interface):
        raise NodeError(f"UDN CIDR must be IPv4: {cidr}")
    cidr = str(iface)
    addr = str(iface.ip)
    return f"""set -euo pipefail
MAC={mac}
CIDR={cidr}
ADDR={addr}
IFACE=""
for d in /sys/class/net/*; do
  n=$(basename "$d")
  [ "$n" = lo ] && continue
  a=$(cat "$d/address" 2>/dev/null || true)
  if [ "$(echo "$a" | tr 'A-F' 'a-f')" = "$MAC" ]; then
    IFACE=$n
    break
  fi
done
if [ -z "$IFACE" ]; then
  echo "no guest NIC with MAC $MAC" >&2
  ip link >&2
  exit 1
fi
if ip -4 -o addr show dev "$IFACE" | grep -q "inet $ADDR/"; then
  echo "UDN $ADDR already on $IFACE"
  exit 0
fi
nmcli con delete ceph-public >/dev/null 2>&1 || true
nmcli con add type ethernet ifname "$IFACE" con-name ceph-public \\
  ipv4.method manual ipv4.addresses "$CIDR" ipv4.never-default yes \\
  connection.autoconnect yes
nmcli con up ceph-public
ip -4 addr show dev "$IFACE"
"""


def ssh_guest_not_ready(err: str) -> bool:
    """True when overlay SSH is not up yet (VMI IP can precede routing/sshd)."""
    err_l = (err or "").lower()
    return any(
        needle in err_l
        for needle in (
            "connection refused",
            "timed out",
            "timeout",
            "no route to host",
            "network is unreachable",
            "host is down",
            "connection reset",
            "connection closed",
            "no matching cipher",
            "kex_exchange_identification",
        )
    )


def pick_vmi_udn_ip(
    interfaces: List[dict],
    udn: Optional[ipaddress.IPv4Network] = None,
) -> Optional[str]:
    """Pick the guest UDN IPv4 used for Ceph (``--mon-ip``, public_network).

    Secondary UDN + l2bridge puts this address on the guest NIC, not on the
    default masquerade overlay. Link-local IPv6 is ignored.
    """
    net = udn or DEFAULT_UDN_SUBNET
    for iface in interfaces or []:
        for ip in _iface_ip_candidates(iface):
            if ":" in ip:
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr in net:
                return ip
    return None


def pick_vmi_ssh_ip(
    interfaces: List[dict],
    udn: Optional[ipaddress.IPv4Network] = None,
) -> Optional[str]:
    """Pick the VMI address the Jenkins agent can SSH to.

    Prefer the default/pod overlay IPv4. Skip the UDN subnet so a secondary
    ``ceph-public`` NIC is not used for SSH.
    """
    udn = udn or DEFAULT_UDN_SUBNET
    default_ipv4s: List[str] = []
    overlay_ipv4s: List[str] = []
    other_ipv4s: List[str] = []
    ipv6s: List[str] = []
    for iface in interfaces or []:
        name = iface.get("name") or ""
        for ip in _iface_ip_candidates(iface):
            if ":" in ip:
                ipv6s.append(ip)
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if name == "default" or addr in OVERLAY_SUBNET:
                if name == "default":
                    default_ipv4s.append(ip)
                overlay_ipv4s.append(ip)
            elif addr in udn:
                continue
            else:
                other_ipv4s.append(ip)
    for group in (default_ipv4s, overlay_ipv4s, other_ipv4s):
        if group:
            return group[0]
    if ipv6s:
        return ipv6s[0]
    return None


def build_virtualmachine_cr(
    node_name: str,
    namespace: str,
    image_name: str,
    storage_class: str,
    network: str,
    root_disk_size: str,
    instancetype_name: str,
    cloud_data: str = "",
    access_modes: Optional[List[str]] = None,
    cloudinit_secret_name: Optional[str] = None,
    precreated_volume_names: Optional[List[str]] = None,
    secondary_network: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a simple KubeVirt VirtualMachine CR with embedded DataVolume templates.

    Compute sizing comes exclusively from ``instancetype_name``
    (``VirtualMachineClusterInstancetype``). Non-root volumes must be pre-created;
    ``precreated_volume_names`` is required (use an empty list when the VM has no
    extra disks).

    Prefer ``cloudinit_secret_name`` (cloudInitNoCloud.secretRef). Inline
    ``userData`` is capped at 2048 bytes by the KubeVirt admission webhook.
    """
    if not instancetype_name:
        raise NodeError(
            "instancetype_name is required; set --custom-config ocpvirt_profile=<name>"
        )
    precreated_volume_names = validate_precreated_volume_names(precreated_volume_names)

    vm_name = _sanitize_k8s_name(node_name)
    root_dv = f"{vm_name}-root"
    root_size = _disk_size_str(root_disk_size)
    modes = access_modes or ["ReadWriteOnce"]

    disks = [
        {"name": "rootdisk", "disk": {"bus": "virtio"}},
        {"name": "cloudinitdisk", "disk": {"bus": "virtio"}},
    ]
    if cloudinit_secret_name:
        # JSON field is secretRef (not userDataSecretRef) on this KubeVirt API.
        cloudinit_vol: Dict[str, Any] = {
            "name": "cloudinitdisk",
            "cloudInitNoCloud": {
                "secretRef": {"name": cloudinit_secret_name},
            },
        }
    else:
        cloudinit_vol = {
            "name": "cloudinitdisk",
            "cloudInitNoCloud": {"userData": cloud_data or "#cloud-config\n"},
        }
    volumes: List[Dict[str, Any]] = [
        {"name": "rootdisk", "dataVolume": {"name": root_dv}},
        cloudinit_vol,
    ]
    data_volume_templates = [
        build_datavolume_spec(
            name=root_dv,
            storage_class=storage_class,
            size=root_size,
            source=_image_source(image_name),
            access_modes=modes,
        )
    ]

    for idx, vol_name in enumerate(precreated_volume_names):
        disk_name = f"disk-{idx}"
        disks.append({"name": disk_name, "disk": {"bus": "virtio"}})
        volumes.append({"name": disk_name, "dataVolume": {"name": vol_name}})

    if not network or network == "default":
        interfaces = [{"name": "default", "masquerade": {}}]
        networks = [{"name": "default", "pod": {}}]
    else:
        interfaces = [{"name": "default", "bridge": {}}]
        networks = [{"name": "default", "multus": {"networkName": network}}]

    if secondary_network and secondary_network not in (network, "default"):
        interfaces.append(
            {"name": secondary_network, "binding": {"name": "l2bridge"}}
        )
        networks.append(
            {
                "name": secondary_network,
                "multus": {"networkName": secondary_network},
            }
        )

    domain: Dict[str, Any] = {
        "devices": {
            "disks": disks,
            "interfaces": interfaces,
            "rng": {},
        },
        "features": {"smm": {"enabled": True}},
        "firmware": {"bootloader": {"efi": {}}},
    }

    vm_spec: Dict[str, Any] = {
        "running": True,
        "instancetype": {
            "kind": KUBEVIRT_CLUSTER_INSTANCETYPE_KIND,
            "name": instancetype_name,
        },
        "dataVolumeTemplates": data_volume_templates,
        "template": {
            "metadata": {
                "labels": {
                    "kubevirt.io/domain": vm_name,
                    "app": "cephci",
                }
            },
            "spec": {
                "domain": domain,
                "networks": networks,
                "volumes": volumes,
            },
        },
    }

    return {
        "apiVersion": f"{KUBEVIRT_GROUP}/{KUBEVIRT_VERSION}",
        "kind": "VirtualMachine",
        "metadata": {
            "name": vm_name,
            "namespace": namespace,
            "labels": {
                "app": "cephci",
                "cephci/node-name": vm_name,
            },
        },
        "spec": vm_spec,
    }


def estimate_pvc_requirement(ceph_cluster: dict) -> int:
    """
    Estimate PersistentVolumeClaims needed for the cluster layout.

    Each node needs 1 root DataVolume PVC plus one PVC per extra volume.
    CDI import may temporarily create prime/scratch PVCs (~1 extra per DV),
    so the peak requirement is about 2x the final PVC count.
    """
    final = 0
    for idx in range(1, 100):
        node = ceph_cluster.get(f"node{idx}")
        if not node:
            break
        final += 1 + int(node.get("no-of-volumes") or 0)
    # Peak during CDI import (DV PVC + temporary prime/scratch)
    return final * 2


def _quota_remaining_pvcs(status: dict) -> Optional[int]:
    """Return remaining PVC slots from a quota status, or None if not limited."""
    hard = (status or {}).get("hard") or {}
    used = (status or {}).get("used") or {}
    if "persistentvolumeclaims" not in hard:
        return None
    try:
        hard_n = int(hard["persistentvolumeclaims"])
        used_n = int(used.get("persistentvolumeclaims") or 0)
    except (TypeError, ValueError):
        return None
    return hard_n - used_n


def ensure_namespace_quota(
    namespace: str, pvc_needed: int, ocp_cred: Optional[dict] = None
) -> None:
    """
    Fail fast when namespace ResourceQuota / AppliedClusterResourceQuota cannot
    satisfy the estimated PVC requirement.

    Raises:
        NodeError: if remaining PVC quota is below pvc_needed.
    """
    if pvc_needed <= 0:
        return

    custom_api, core_api = get_k8s_clients(ocp_cred)
    remaining_values: List[tuple] = []

    try:
        for rq in core_api.list_namespaced_resource_quota(namespace).items:
            status = rq.status.to_dict() if rq.status else {}
            rem = _quota_remaining_pvcs(status)
            if rem is not None:
                remaining_values.append((f"ResourceQuota/{rq.metadata.name}", rem))
    except Exception as exc:
        LOG.warning(f"Unable to list ResourceQuota in {namespace}: {exc}")

    # OpenShift AppliedClusterResourceQuota (tenant PVC caps)
    try:
        resp = custom_api.list_namespaced_custom_object(
            group="quota.openshift.io",
            version="v1",
            namespace=namespace,
            plural="appliedclusterresourcequotas",
        )
        for item in resp.get("items") or []:
            name = (item.get("metadata") or {}).get("name", "unknown")
            total = (item.get("status") or {}).get("total") or {}
            rem = _quota_remaining_pvcs(total)
            if rem is not None:
                remaining_values.append((f"AppliedClusterResourceQuota/{name}", rem))
    except Exception as exc:
        LOG.debug(f"AppliedClusterResourceQuota not available or failed: {exc}")

    if not remaining_values:
        LOG.info(f"No PVC ResourceQuota found in {namespace}; skipping quota pre-check")
        return

    # Binding constraint is the tightest remaining allowance
    quota_name, remaining = min(remaining_values, key=lambda x: x[1])
    LOG.info(
        f"PVC quota check: need {pvc_needed}, remaining {remaining} ({quota_name})"
    )
    if remaining < pvc_needed:
        raise NodeError(
            f"Insufficient PVC quota in namespace {namespace}: "
            f"need {pvc_needed} PVCs (including CDI import headroom), "
            f"but only {remaining} remaining under {quota_name}. "
            f"Reduce node/volume count in --global-conf or free PVCs, then retry."
        )


def validate_precreated_volume_names(
    precreated_volume_names: Optional[List[str]],
) -> List[str]:
    """
    Validate pre-created non-root DataVolume names for VM attach.

    Args:
        precreated_volume_names: List of existing DataVolume names. Required;
            pass an empty list when the VM has no extra volumes.

    Returns:
        Normalized list copy.

    Raises:
        NodeError: if ``precreated_volume_names`` is missing or not a list.
    """
    if precreated_volume_names is None:
        raise NodeError(
            "precreated_volume_names is required for OCP Virt VM create "
            "(pass [] when no extra volumes are needed)"
        )
    if not isinstance(precreated_volume_names, list):
        raise NodeError("precreated_volume_names must be a list")
    return list(precreated_volume_names)


def validate_ocpvirt_credentials(osp_cred: dict) -> dict:
    """
    Validate auth-only ``--osp-cred`` file contents for ``--cloud ocpvirt``.

    Namespace, storage, and network settings belong in ``conf/ocpvirt/<name>.yaml``
    and are selected via ``--custom-config ocpvirt_namespace=<name>``.

    Args:
        osp_cred: Parsed osp-cred YAML (must contain globals.ocpvirt-credentials).

    Returns:
        The validated auth section from ``ocpvirt-credentials``.

    Raises:
        NodeError: if required sections or keys are missing.
    """
    if not osp_cred:
        raise NodeError("ocpvirt-credentials file is required for --cloud ocpvirt")

    glbs = osp_cred.get("globals")
    if not glbs:
        raise NodeError("Missing 'globals' section in OCP Virt credentials file")

    ocp_cfg = glbs.get("ocpvirt-credentials")
    if not ocp_cfg:
        raise NodeError("Missing 'ocpvirt-credentials' section in globals")

    if not ocp_cfg.get("token"):
        raise NodeError("Missing 'token' in ocpvirt-credentials")

    return ocp_cfg


def _validate_datasource_url(url: str, label: str) -> None:
    url_text = str(url).strip()
    if not url_text.startswith("datasource://"):
        raise NodeError(f"{label} must start with datasource://")
    rest = url_text[len("datasource://") :].strip("/")
    if not rest or "/" not in rest:
        raise NodeError(f"{label} must be a full datasource://<namespace>/<name> URL")


def resolve_ocpvirt_image_name(image_name: str, ocp_cred: dict) -> str:
    """
    Resolve inventory image-name to a full datasource URL when needed.

    Short names like ``datasource://rhel9`` are expanded using the ``datasources``
    map in ``conf/ocpvirt/<name>.yaml``. Inventory may also use the full URL
    directly: ``datasource://<namespace>/<name>``.
    """
    image = str(image_name).strip()
    if not image.startswith("datasource://"):
        return image

    rest = image[len("datasource://") :].strip("/")
    if "/" in rest:
        _validate_datasource_url(image, "image-name")
        return image

    datasources = ocp_cred.get("datasources") or {}
    if not isinstance(datasources, dict):
        raise NodeError("datasources must be a mapping in conf/ocpvirt/<name>.yaml")

    full_url = datasources.get(rest)
    if not full_url:
        raise NodeError(
            f"inventory image-name {image_name!r} requires a full "
            f"datasource://<namespace>/<name> URL or datasources.{rest} in "
            "conf/ocpvirt/<name>.yaml"
        )

    full_url = str(full_url).strip()
    _validate_datasource_url(full_url, f"datasources.{rest}")
    return full_url


def validate_ocpvirt_namespace_config(namespace_config: dict) -> dict:
    """
    Validate namespace template loaded from ``conf/ocpvirt/<name>.yaml``.

    Raises:
        NodeError: if required keys are missing.
    """
    if not namespace_config:
        raise NodeError("OCP Virt namespace config file is empty")

    if not namespace_config.get("namespace"):
        raise NodeError("namespace is required in conf/ocpvirt/<name>.yaml")

    if not namespace_config.get("server"):
        raise NodeError("server is required in conf/ocpvirt/<name>.yaml")

    if not namespace_config.get("storage_class"):
        raise NodeError("storage_class is required in conf/ocpvirt/<name>.yaml")

    datasources = namespace_config.get("datasources") or {}
    if datasources and not isinstance(datasources, dict):
        raise NodeError("datasources must be a mapping in conf/ocpvirt/<name>.yaml")
    for key, url in datasources.items():
        _validate_datasource_url(url, f"datasources.{key}")

    return namespace_config


def list_cluster_instancetypes(custom_api) -> List[str]:
    """Return sorted names of VirtualMachineClusterInstancetypes on the cluster."""
    resp = custom_api.list_cluster_custom_object(
        group=INSTANCETYPE_GROUP,
        version=INSTANCETYPE_VERSION,
        plural="virtualmachineclusterinstancetypes",
    )
    items = resp.get("items") or []
    return sorted(
        name for item in items if (name := (item.get("metadata") or {}).get("name"))
    )


def resolve_ocpvirt_instancetype(custom_api, profile_name: str) -> str:
    """
    Validate ``ocpvirt_profile`` against cluster VirtualMachineClusterInstancetypes.

    Raises:
        NodeError: if the profile name does not exist on the cluster.
    """
    try:
        available = list_cluster_instancetypes(custom_api)
    except Exception as exc:
        raise NodeError(
            "Failed to list VirtualMachineClusterInstancetypes on cluster"
        ) from exc
    if profile_name not in available:
        raise NodeError(
            f"Unknown ocpvirt_profile {profile_name!r}; "
            f"available instance types: {', '.join(available) or '(none)'}"
        )
    return profile_name


def apply_ocpvirt_vm_profile(params: dict, ocp_cred: dict, custom_config=None) -> dict:
    """
    Apply ``--custom-config ocpvirt_profile=<name>`` using cluster instance types.

    Defaults to ``o1.large`` when no profile is given.
    """
    profile_name = process_ocpvirt_custom_config(custom_config)["ocpvirt_profile"]
    custom_api, _ = get_k8s_clients(ocp_cred)
    instancetype_name = resolve_ocpvirt_instancetype(custom_api, profile_name)
    updated = dict(params)
    updated["instancetype"] = instancetype_name
    LOG.info(
        f"Using OCP Virt cluster instance type {instancetype_name} "
        f"(VirtualMachineClusterInstancetype)"
    )
    return updated


def load_ocpvirt_namespace_config(custom_config) -> dict:
    """
    Load OCP Virt namespace settings from ``conf/ocpvirt/<name>.yaml``.

    The template name comes from ``--custom-config ocpvirt_namespace=<name>``.

    Raises:
        NodeError: if ``ocpvirt_namespace`` is missing or the file is not found.
    """
    from utility.utils import parse_custom_config_list

    overrides = parse_custom_config_list(custom_config)
    namespace_name = overrides.get("ocpvirt_namespace")
    if not namespace_name:
        raise NodeError(
            "ocpvirt_namespace is required in --custom-config "
            "(e.g. --custom-config ocpvirt_namespace=rdu3_ceph_jenkins)"
        )

    platform_conf = REPO_ROOT.joinpath(f"conf/ocpvirt/{namespace_name}.yaml")
    if not platform_conf.is_file():
        raise NodeError(
            f"OCP Virt namespace config not found: {platform_conf}. "
            f"Expected conf/ocpvirt/{namespace_name}.yaml"
        )

    with platform_conf.open() as fh:
        namespace_config = yaml.safe_load(fh) or {}

    return validate_ocpvirt_namespace_config(namespace_config)


def merge_ocpvirt_credentials(auth_cred: dict, namespace_config: dict) -> dict:
    """Merge auth-only osp-cred with a ``conf/ocpvirt`` namespace template."""
    merged = dict(namespace_config)
    merged.update(auth_cred)
    return merged


def resolve_ocpvirt_credentials(osp_cred: dict, custom_config=None) -> dict:
    """
    Resolve full OCP Virt credentials for API calls and provisioning.

    Combines auth from ``--osp-cred`` with namespace settings from
    ``conf/ocpvirt/<ocpvirt_namespace>.yaml``.
    """
    auth_cred = validate_ocpvirt_credentials(osp_cred)
    namespace_config = load_ocpvirt_namespace_config(custom_config)
    return merge_ocpvirt_credentials(auth_cred, namespace_config)


def validate_ocpvirt_inventory(
    inventory: dict, ceph_cluster: dict, ocp_cred: dict
) -> dict:
    """
    Validate inventory and cluster layout for OCP Virt provisioning.

    Args:
        inventory: Parsed inventory YAML from ``--inventory``.
        ceph_cluster: ``ceph-cluster`` section from ``--global-conf``.
        ocp_cred: Validated ``ocpvirt-credentials`` dict.

    Returns:
        Shared create parameters derived from inventory / cluster conf.

    Raises:
        NodeError: if required inventory keys are missing or invalid.
    """
    if not inventory:
        raise NodeError("inventory file is required for OCP Virt provisioning")

    instance = inventory.get("instance") or {}
    inv_create = instance.get("create") or {}

    image_name = ceph_cluster.get("image-name") or inv_create.get("image-name")
    if not image_name:
        raise NodeError(
            "OCP Virt create: image-name is required in inventory or cluster conf"
        )

    image_name = resolve_ocpvirt_image_name(image_name, ocp_cred)

    params = {
        "cloud-data": instance.get("setup", ""),
        "image-name": image_name,
    }

    return params


def validate_ocpvirt_node_params(params: dict) -> None:
    """
    Validate per-node provisioning params before OCP Virt VM create.

    Raises:
        NodeError: if required keys are missing or invalid.
    """
    validate_precreated_volume_names(params.get("precreated_volume_names"))

    for key in ("node-name", "image-name", "ocp-cred"):
        if not params.get(key):
            raise NodeError(f"{key} is required for OCP Virt node setup")


def process_ocpvirt_custom_config(custom_config):
    """
    Parse OCP Virt batch settings from --custom-config.

    Supported keys:
        ocpvirt_namespace: Name of conf/ocpvirt/<name>.yaml (required for create/cleanup).
        ocpvirt_profile: VirtualMachineClusterInstancetype name (default o1.large).
        pvc_batch_size (default 3): non-root DataVolumes created per batch.
        vm_batch_size (default 1): VirtualMachines created per batch.
    """
    from utility.utils import parse_custom_config_list

    overrides = parse_custom_config_list(custom_config)
    try:
        pvc_batch_size = int(overrides.get("pvc_batch_size", 3))
    except (TypeError, ValueError):
        pvc_batch_size = 3
    try:
        vm_batch_size = int(overrides.get("vm_batch_size", 1))
    except (TypeError, ValueError):
        vm_batch_size = 1
    return {
        "pvc_batch_size": max(1, pvc_batch_size),
        "vm_batch_size": max(1, vm_batch_size),
        "ocpvirt_profile": overrides.get("ocpvirt_profile") or DEFAULT_OCPVIRT_PROFILE,
    }


def non_root_datavolume_names(node_name: str, no_of_volumes: int) -> List[str]:
    """Return blank DataVolume names for a VM's non-root disks."""
    vm_name = _sanitize_k8s_name(node_name)
    count = int(no_of_volumes or 0)
    return [f"{vm_name}-vol-{idx}" for idx in range(count)]


def _get_datavolume(custom_api, namespace: str, name: str) -> Optional[dict]:
    try:
        return custom_api.get_namespaced_custom_object(
            group=CDI_GROUP,
            version=CDI_VERSION,
            namespace=namespace,
            plural="datavolumes",
            name=name,
        )
    except Exception as exc:
        if getattr(exc, "status", None) == 404:
            return None
        raise


def wait_for_datavolume_succeeded(
    custom_api,
    namespace: str,
    name: str,
    timeout: int = VM_POLL_TIMEOUT,
) -> None:
    """Wait until a DataVolume reaches phase Succeeded."""
    for w in WaitUntil(timeout=timeout, interval=VM_POLL_INTERVAL):
        dv = _get_datavolume(custom_api, namespace, name)
        if not dv:
            if w._attempt == 1 or w._attempt % 6 == 0:
                LOG.info(f"Waiting for DataVolume {name}: not found yet")
            continue
        phase = (dv.get("status") or {}).get("phase", "")
        if phase == "Succeeded":
            LOG.info(f"DataVolume {name} is ready")
            return
        if phase in ("Failed", "Error"):
            raise NodeError(f"DataVolume {name} failed with phase {phase}")
        if w._attempt == 1 or w._attempt % 6 == 0:
            LOG.info(f"Waiting for DataVolume {name}: phase={phase or 'unknown'}")
    if w.expired:
        raise NodeError(f"DataVolume {name} not ready within {timeout}s")


def create_blank_datavolume(
    ocp_cred: dict,
    vol_name: str,
    size_of_disks: Any,
    storage_class: Optional[str] = None,
    access_modes: Optional[List[str]] = None,
) -> None:
    """Create a standalone blank DataVolume and wait until it is bound."""
    custom_api, _ = get_k8s_clients(ocp_cred)
    namespace = ocp_cred["namespace"]
    storage_class = storage_class or ocp_cred.get("storage_class")
    modes = access_modes or ocp_cred.get("access_modes") or ["ReadWriteOnce"]
    if isinstance(modes, str):
        modes = [modes]
    if not storage_class:
        raise NodeError("storage_class is required in ocpvirt-credentials")

    dv_body = {
        "apiVersion": f"{CDI_GROUP}/{CDI_VERSION}",
        "kind": "DataVolume",
        "metadata": {
            "name": vol_name,
            "namespace": namespace,
            "labels": {
                "app": "cephci",
                "cephci/precreated-volume": "true",
            },
        },
        "spec": build_datavolume_spec(
            name=vol_name,
            storage_class=storage_class,
            size=_disk_size_str(size_of_disks, default="15Gi"),
            source=None,
            access_modes=modes,
        )["spec"],
    }
    LOG.info(f"Creating blank DataVolume {vol_name} in namespace {namespace}")
    try:
        custom_api.create_namespaced_custom_object(
            group=CDI_GROUP,
            version=CDI_VERSION,
            namespace=namespace,
            plural="datavolumes",
            body=dv_body,
        )
    except Exception as exc:
        if getattr(exc, "status", None) != 409:
            raise NodeError(f"Failed to create DataVolume {vol_name}: {exc}") from exc
        LOG.warning(f"DataVolume {vol_name} already exists; waiting for readiness")
    wait_for_datavolume_succeeded(custom_api, namespace, vol_name)


def delete_datavolume(ocp_cred: dict, vol_name: str) -> None:
    """Best-effort delete of a standalone DataVolume."""
    custom_api, _ = get_k8s_clients(ocp_cred)
    namespace = ocp_cred["namespace"]
    try:
        custom_api.delete_namespaced_custom_object(
            group=CDI_GROUP,
            version=CDI_VERSION,
            namespace=namespace,
            plural="datavolumes",
            name=vol_name,
            body={},
        )
        LOG.info(f"Deleted DataVolume {vol_name}")
    except Exception as exc:
        if getattr(exc, "status", None) != 404:
            LOG.warning(f"delete DataVolume {vol_name} failed: {exc}")


def cleanup_precreated_datavolumes(ocp_cred: dict, volume_names: List[str]) -> None:
    """Delete pre-created non-root DataVolumes (best effort)."""
    for vol_name in volume_names or []:
        delete_datavolume(ocp_cred, vol_name)


def datavolume_names_from_vm(vm: dict) -> List[str]:
    """
    Return all DataVolume names referenced by a VirtualMachine spec.

    Includes root and non-root disks from ``dataVolumeTemplates`` and
    ``template.spec.volumes`` (pre-created volumes are only listed in volumes).
    """
    if not vm:
        return []
    names: List[str] = []
    seen = set()
    for template in vm.get("spec", {}).get("dataVolumeTemplates") or []:
        name = (template.get("metadata") or {}).get("name")
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    template_spec = (vm.get("spec", {}).get("template") or {}).get("spec") or {}
    for volume in template_spec.get("volumes") or []:
        name = (volume.get("dataVolume") or {}).get("name")
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def cleanup_datavolumes_matching_pattern(ocp_cred: dict, pattern: str) -> None:
    """Delete standalone DataVolumes whose name contains ``pattern`` (best effort)."""
    if not pattern:
        return
    custom_api, _ = get_k8s_clients(ocp_cred)
    namespace = ocp_cred["namespace"]
    pat = pattern.lower()
    try:
        resp = custom_api.list_namespaced_custom_object(
            group=CDI_GROUP,
            version=CDI_VERSION,
            namespace=namespace,
            plural="datavolumes",
        )
    except Exception as exc:
        LOG.warning(f"Failed to list DataVolumes in {namespace}: {exc}")
        return
    for item in resp.get("items") or []:
        name = (item.get("metadata") or {}).get("name") or ""
        if pat in name.lower():
            delete_datavolume(ocp_cred, name)


def cleanup_ocpvirt_ceph_nodes(osp_cred, pattern, custom_config=None):
    """
    Delete VirtualMachines (and their cloud-init Secrets) whose name contains pattern.

    Also removes orphaned ``*-cloudinit`` Secrets matching the pattern (e.g. when
    Secret create succeeded but VM create failed) and standalone DataVolumes /
    PVCs left from pre-created non-root disks.

    Args:
        osp_cred: Auth-only credential file with globals["ocpvirt-credentials"].
        pattern: Substring to match against VM / Secret names.
        custom_config: CLI options; must include ocpvirt_namespace=<name>.
    """
    LOG.info(f"Destroying existing OCP Virt VMs matching pattern {pattern}")
    ocp_cfg = resolve_ocpvirt_credentials(osp_cred, custom_config)
    namespace = ocp_cfg["namespace"]

    custom_api, core_api = get_k8s_clients(ocp_cfg)
    try:
        resp = custom_api.list_namespaced_custom_object(
            group=KUBEVIRT_GROUP,
            version=KUBEVIRT_VERSION,
            namespace=namespace,
            plural="virtualmachines",
        )
    except Exception as exc:
        LOG.warning(f"Failed to list VirtualMachines in {namespace}: {exc}")
        return

    items = resp.get("items") or []
    matched = [
        vm
        for vm in items
        if pattern
        and pattern.lower() in (vm.get("metadata", {}).get("name") or "").lower()
    ]
    LOG.info(
        f"Found {len(matched)} VMs matching pattern '{pattern}' in namespace {namespace}"
    )

    counter = 0
    with parallel() as p:
        for vm in matched:
            sleep(counter * 2)
            name = vm["metadata"]["name"]
            node = CephVMNodeOCP(ocp_cred=ocp_cfg, node=vm)
            p.spawn(node.delete)
            LOG.info(f"Scheduled delete for VM {name}")
            counter += 1

    # Sweep orphan / leftover cloud-init Secrets (VM may never have been created).
    if pattern:
        pat = pattern.lower()
        try:
            secrets = core_api.list_namespaced_secret(namespace).items
        except Exception as exc:
            LOG.warning(f"Failed to list Secrets in {namespace}: {exc}")
            secrets = []
        for sec in secrets:
            name = sec.metadata.name or ""
            labels = sec.metadata.labels or {}
            is_cephci_cloudinit = labels.get("cephci/cloudinit") == "true" or (
                name.endswith("-cloudinit") and name.startswith("ceph-")
            )
            if is_cephci_cloudinit and pat in name.lower():
                try:
                    core_api.delete_namespaced_secret(name, namespace)
                    LOG.info(f"Deleted cloud-init Secret {name}")
                except Exception as exc:
                    if getattr(exc, "status", None) != 404:
                        LOG.warning(f"delete cloud-init Secret {name} failed: {exc}")

    cleanup_datavolumes_matching_pattern(ocp_cfg, pattern)

    LOG.info(f"Done cleaning up OCP Virt nodes with pattern {pattern}")


class CephVMNodeOCP:
    """Represent the VM node required for cephci on OCP Virtualization."""

    def __init__(
        self,
        ocp_cred: dict,
        node: Optional[dict] = None,
        node_name: Optional[str] = None,
    ) -> None:
        """
        Initialize the instance.

        Args:
            ocp_cred: ocpvirt-credentials dict (namespace, storage_class, ...).
            node: Optional existing VirtualMachine object (for cleanup).
            node_name: Optional VM name to look up in the namespace.
        """
        self._ocp_cred = ocp_cred
        self.namespace = ocp_cred["namespace"]
        self._subnet: str = ""
        self._roles: list = list()
        self._volumes: list = list()
        self._precreated_volumes: list = list()
        self.node: Optional[dict] = None
        self.root_login: bool = True
        self.osd_scenario = None
        self.location = None
        self.id = None

        self.custom_api, self.core_api = get_k8s_clients(ocp_cred)

        if node:
            self.node = node
        elif node_name:
            self.node = self._get_vm(_sanitize_k8s_name(node_name))

    def __getstate__(self) -> dict:
        """Exclude non-picklable API clients."""
        state = self.__dict__.copy()
        state.pop("custom_api", None)
        state.pop("core_api", None)
        return state

    def __setstate__(self, state: dict) -> None:
        """Restore state and recreate API clients."""
        self.__dict__.update(state)
        self.custom_api, self.core_api = get_k8s_clients(self._ocp_cred)
        # Reuse pickles may have cached the overlay SSH IP as ip_address.
        self._cached_ip = None
        self._cached_ssh_ip = None

    @property
    def ssh_ip(self) -> str:
        """Overlay IPv4 the Jenkins agent can SSH to (not the UDN)."""
        cached = getattr(self, "_cached_ssh_ip", None)
        if cached:
            return cached
        ip = (
            pick_vmi_ssh_ip(
                self._vmi_interfaces(), udn=udn_network(self._ocp_cred)
            )
            or ""
        )
        if ip:
            self._cached_ssh_ip = ip
        return ip

    @property
    def ip_address(self) -> str:
        """Ceph bind address: UDN IPv4 when present, else the SSH overlay IP."""
        cached = getattr(self, "_cached_ip", None)
        if cached:
            return cached
        udn_ip = pick_vmi_udn_ip(
            self._vmi_interfaces(), udn=udn_network(self._ocp_cred)
        )
        if udn_ip:
            self._cached_ip = udn_ip
            return udn_ip
        return self.ssh_ip

    @property
    def hostname(self) -> str:
        """Return the VM name (used as hostname until SSH connect refreshes it)."""
        if not self.node:
            return ""
        return self.node.get("metadata", {}).get("name", "")

    @property
    def volumes(self) -> List:
        """Return list of extra (non-root) data volume names attached to the VM."""
        if self._volumes:
            return self._volumes
        if not self.node:
            return []
        templates = self.node.get("spec", {}).get("dataVolumeTemplates") or []
        root_name = f"{self.hostname}-root"
        self._volumes = [
            t.get("metadata", {}).get("name")
            for t in templates
            if t.get("metadata", {}).get("name")
            and t.get("metadata", {}).get("name") != root_name
        ]
        return self._volumes

    @property
    def subnet(self) -> str:
        """Return subnet CIDR if known; empty for pod network."""
        if self._subnet:
            return self._subnet
        ip = self.ip_address
        if ip:
            self._subnet = self._derive_subnet(ip)
        return self._subnet

    def _derive_subnet(self, ip: str) -> str:
        """Derive IPv4 CIDR for the guest address.

        Prefer an explicit ``subnet`` / ``network_cidr`` from ocpvirt-credentials.
        Otherwise assume /24, which matches Multus L2 bridge pools and what
        cephadm auto-detects for public_network.
        """
        for key in ("subnet", "network_cidr"):
            cidr = self._ocp_cred.get(key)
            if cidr:
                return str(cidr)
        if ":" in ip:
            return ""
        try:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            return ""

    @property
    def shortname(self) -> str:
        """Return the short form of the hostname."""
        return self.hostname.split(".")[0] if self.hostname else ""

    @property
    def no_of_volumes(self) -> int:
        """Return the number of extra volumes attached to the VM."""
        return len(self.volumes)

    @property
    def role(self) -> List:
        """Return the Ceph roles of the instance."""
        return self._roles

    @role.setter
    def role(self, roles: list) -> None:
        """Set the roles for the VM."""
        self._roles = deepcopy(roles)

    @property
    def node_type(self) -> str:
        """Return the provider type."""
        return "ocpvirt"

    def create(
        self,
        node_name: str,
        image_name: str,
        cloud_data: str = "",
        size_of_disks: int = 0,
        no_of_volumes: int = 0,
        storage_class: Optional[str] = None,
        network: Optional[str] = None,
        precreated_volume_names: Optional[List[str]] = None,
        instancetype: str = "",
    ) -> None:
        """
        Create a VirtualMachine (and DataVolumes) on OCP Virtualization.

        Args:
            node_name: Desired VM name (sanitized for K8s).
            image_name: Container-disk / HTTP image URL from inventory.
            cloud_data: cloud-init userdata from inventory.
            size_of_disks: Size in GiB for each additional blank disk.
            no_of_volumes: Number of additional blank DataVolumes.
            storage_class / network:
                Optional overrides; defaults come from ocpvirt-credentials.
            precreated_volume_names:
                Required list of existing blank DataVolume names to attach.
                Pass an empty list when the VM has no extra volumes.
            instancetype:
                ``VirtualMachineClusterInstancetype`` name from
                ``--custom-config ocpvirt_profile=<name>`` (required).
        """
        if not instancetype:
            raise NodeError(
                "instancetype is required for OCP Virt VM create; "
                "set --custom-config ocpvirt_profile=<name>"
            )
        precreated = validate_precreated_volume_names(precreated_volume_names)
        self._precreated_volumes = precreated

        cred = self._ocp_cred
        storage_class = storage_class or cred.get("storage_class")
        network = network if network is not None else cred.get("network", "default")
        secondary_network = cred.get("secondary_network")
        root_disk_size = cred.get("root_disk_size") or DEFAULT_OCPVIRT_ROOT_DISK_SIZE
        access_modes = cred.get("access_modes") or ["ReadWriteOnce"]
        if isinstance(access_modes, str):
            access_modes = [access_modes]

        if not storage_class:
            raise NodeError("storage_class is required in conf/ocpvirt/<name>.yaml")

        vm_name = _sanitize_k8s_name(node_name)
        secret_name = _cloudinit_secret_name(vm_name)
        self._ensure_cloudinit_secret(secret_name, cloud_data)

        resolved_image_name = resolve_ocpvirt_image_name(image_name, cred)
        vm_body = build_virtualmachine_cr(
            node_name=node_name,
            namespace=self.namespace,
            image_name=resolved_image_name,
            storage_class=storage_class,
            network=network,
            root_disk_size=root_disk_size,
            access_modes=access_modes,
            cloudinit_secret_name=secret_name,
            precreated_volume_names=precreated,
            instancetype_name=instancetype,
            secondary_network=secondary_network,
        )
        LOG.info(f"Creating VirtualMachine {vm_name} in namespace {self.namespace}")

        try:
            try:
                self.custom_api.create_namespaced_custom_object(
                    group=KUBEVIRT_GROUP,
                    version=KUBEVIRT_VERSION,
                    namespace=self.namespace,
                    plural="virtualmachines",
                    body=vm_body,
                )
            except Exception as exc:
                if getattr(exc, "status", None) != 409:
                    raise
                # Retry/racer: VM is already in the API. Keep the Secret and wait.
                LOG.warning(
                    f"VirtualMachine {vm_name} already exists; "
                    "waiting for it to become ready"
                )
            # Bind node early so delete() on retry actually removes the VM.
            self.node = self._get_vm(vm_name)
            self._wait_until_vm_ready(vm_name)
            self._wait_until_ip_known(vm_name)
            self.node = self._get_vm(vm_name)
            if not self.node:
                raise NodeError(
                    f"Failed to fetch VirtualMachine {vm_name} after create"
                )
            if secondary_network:
                self._ensure_guest_udn_ipv4(vm_name, secondary_network)
                self._cached_ip = None
                self._wait_until_udn_ip_known(vm_name)
            ceph_ip = self.ip_address
            ssh_ip = self.ssh_ip
            if ceph_ip:
                self._subnet = self._derive_subnet(ceph_ip)
            if precreated:
                self._volumes = list(precreated)
            LOG.info(
                f"Created VirtualMachine {vm_name} ssh={ssh_ip} ceph={ceph_ip}"
                + (f" subnet {self._subnet}" if self._subnet else "")
            )
        except NodeError:
            # virt-launcher mounts the cloud-init Secret; drop it only if the VM
            # is gone. delete() removes the Secret after the VM is deleted.
            if not self._get_vm(vm_name):
                self._delete_cloudinit_secret(secret_name)
            else:
                self.node = self.node or self._get_vm(vm_name)
                LOG.warning(
                    f"Leaving VirtualMachine {vm_name} and cloud-init Secret "
                    f"{secret_name} in place after create wait failure"
                )
            raise
        except Exception as exc:
            LOG.error(exc, exc_info=True)
            if not self._get_vm(vm_name):
                self._delete_cloudinit_secret(secret_name)
            else:
                self.node = self.node or self._get_vm(vm_name)
            raise NodeError(f"Failed to create VM {vm_name}: {exc}") from exc

    def _ensure_cloudinit_secret(self, secret_name: str, cloud_data: str) -> None:
        """Create/replace Secret holding cloud-init userdata (avoids 2048-byte inline cap)."""
        body = client.V1Secret(
            api_version="v1",
            kind="Secret",
            metadata=client.V1ObjectMeta(
                name=secret_name,
                namespace=self.namespace,
                labels={"app": "cephci", "cephci/cloudinit": "true"},
            ),
            type="Opaque",
            string_data={"userdata": cloud_data or "#cloud-config\n"},
        )
        try:
            self.core_api.create_namespaced_secret(self.namespace, body)
            LOG.info(f"Created cloud-init Secret {secret_name}")
        except Exception as exc:
            if getattr(exc, "status", None) == 409:
                self.core_api.replace_namespaced_secret(
                    secret_name, self.namespace, body
                )
                LOG.info(f"Replaced cloud-init Secret {secret_name}")
            else:
                raise NodeError(
                    f"Failed to create cloud-init Secret {secret_name}: {exc}"
                ) from exc

    def _delete_cloudinit_secret(self, secret_name: str) -> None:
        """Best-effort delete of the VM cloud-init Secret."""
        try:
            self.core_api.delete_namespaced_secret(secret_name, self.namespace)
            LOG.info(f"Deleted cloud-init Secret {secret_name}")
        except Exception as exc:
            if getattr(exc, "status", None) != 404:
                LOG.warning(f"delete cloud-init Secret {secret_name} failed: {exc}")

    def delete(self, keep_precreated_volumes: bool = False) -> None:
        """Delete the VirtualMachine (DataVolumes owned via templates are cleaned up).

        Args:
            keep_precreated_volumes: If True, leave batch-created blank disks.
                Used on create retry so the next attempt can reattach them.
        """
        if not self.node:
            return

        vm_name = self.node.get("metadata", {}).get("name")
        if not vm_name:
            self.node = None
            return

        datavolume_names = list(
            dict.fromkeys(
                (self._precreated_volumes or []) + datavolume_names_from_vm(self.node)
            )
        )

        LOG.info(f"Deleting VirtualMachine {vm_name} in {self.namespace}")
        try:
            self.custom_api.delete_namespaced_custom_object(
                group=KUBEVIRT_GROUP,
                version=KUBEVIRT_VERSION,
                namespace=self.namespace,
                plural="virtualmachines",
                name=vm_name,
                body={},
            )
        except Exception as exc:
            # 404 is fine (already gone)
            status = getattr(exc, "status", None)
            if status == 404:
                LOG.info(f"VirtualMachine {vm_name} already deleted")
            else:
                LOG.warning(f"delete VirtualMachine failed: {exc}")
                raise NodeDeleteFailure(f"Failed to delete {vm_name}: {exc}") from exc

        self._wait_until_vm_deleted(vm_name)
        if keep_precreated_volumes:
            keep = set(self._precreated_volumes or [])
            to_drop = [n for n in datavolume_names if n not in keep]
            LOG.info(
                f"Keeping {len(keep)} precreated DataVolume(s) for VM create retry"
            )
            if to_drop:
                cleanup_precreated_datavolumes(self._ocp_cred, to_drop)
        else:
            cleanup_precreated_datavolumes(self._ocp_cred, datavolume_names)
            self._precreated_volumes = []
        # Prefer secret name referenced by the VM; fall back to naming convention.
        secret_name = _cloudinit_secret_name(vm_name)
        try:
            for vol in (
                self.node.get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("volumes")
                or []
            ):
                ref = (vol.get("cloudInitNoCloud") or {}).get("secretRef") or {}
                if ref.get("name"):
                    secret_name = ref["name"]
                    break
        except Exception:
            pass
        self._delete_cloudinit_secret(secret_name)
        self.node = None
        LOG.info(f"Successfully removed {vm_name}")

    def shutdown(self, wait: bool = False) -> None:
        """Stop the VirtualMachine by setting spec.running=False."""
        if not self.node:
            return
        vm_name = self.hostname
        LOG.info(f"Shutting down VirtualMachine {vm_name}")
        self._patch_running(vm_name, False)
        if wait:
            self._wait_until_vmi_phase(vm_name, "Succeeded", allow_missing=True)

    def power_on(self) -> None:
        """Start the VirtualMachine by setting spec.running=True."""
        if not self.node:
            return
        vm_name = self.hostname
        LOG.info(f"Powering on VirtualMachine {vm_name}")
        self._patch_running(vm_name, True)
        self._wait_until_vm_ready(vm_name)
        self.node = self._get_vm(vm_name)

    def get_private_ip(self) -> str:
        """Return the SSH overlay IP (not the UDN Ceph address)."""
        return self.ssh_ip

    # --- private helpers ---

    def _patch_running(self, vm_name: str, running: bool) -> None:
        body = {"spec": {"running": running}}
        self.custom_api.patch_namespaced_custom_object(
            group=KUBEVIRT_GROUP,
            version=KUBEVIRT_VERSION,
            namespace=self.namespace,
            plural="virtualmachines",
            name=vm_name,
            body=body,
        )

    def _get_vm(self, vm_name: str) -> Optional[dict]:
        try:
            return self.custom_api.get_namespaced_custom_object(
                group=KUBEVIRT_GROUP,
                version=KUBEVIRT_VERSION,
                namespace=self.namespace,
                plural="virtualmachines",
                name=vm_name,
            )
        except Exception as exc:
            status = getattr(exc, "status", None)
            if status == 404:
                return None
            LOG.warning(f"get VirtualMachine {vm_name} failed: {exc}")
            return None

    def _get_vmi(self, vm_name: str) -> Optional[dict]:
        try:
            return self.custom_api.get_namespaced_custom_object(
                group=KUBEVIRT_GROUP,
                version=KUBEVIRT_VERSION,
                namespace=self.namespace,
                plural="virtualmachineinstances",
                name=vm_name,
            )
        except Exception as exc:
            status = getattr(exc, "status", None)
            if status == 404:
                return None
            LOG.warning(f"get VMI {vm_name} failed: {exc}")
            return None

    def _vmi_interfaces(self) -> List[dict]:
        if not self.node:
            return []
        vm_name = self.node.get("metadata", {}).get("name")
        if not vm_name:
            return []
        vmi = self._get_vmi(vm_name)
        if not vmi:
            return []
        return (vmi.get("status") or {}).get("interfaces") or []

    def _get_vmi_ip(self) -> Optional[str]:
        """SSH overlay IPv4 (create wait). Prefer ``ip_address`` for Ceph."""
        return pick_vmi_ssh_ip(
            self._vmi_interfaces(), udn=udn_network(self._ocp_cred)
        )

    def _virt_launcher_pod(self, vm_name: str) -> Optional[Any]:
        try:
            pods = self.core_api.list_namespaced_pod(
                self.namespace,
                label_selector=f"kubevirt.io/domain={vm_name}",
            )
        except Exception as exc:
            LOG.warning(f"list virt-launcher for {vm_name} failed: {exc}")
            return None
        items = getattr(pods, "items", None) or []
        return items[0] if items else None

    def _ovn_secondary_cidr(self, vm_name: str, network_name: str) -> Optional[str]:
        pod = self._virt_launcher_pod(vm_name)
        if pod is None:
            return None
        annotations = pod.metadata.annotations or {}
        return parse_ovn_secondary_cidr(
            annotations.get("k8s.ovn.org/pod-networks") or "",
            self.namespace,
            network_name,
        )

    def _secondary_iface_mac(self, network_name: str) -> Optional[str]:
        for iface in self._vmi_interfaces():
            if iface.get("name") == network_name and iface.get("mac"):
                return str(iface["mac"])
        vmi_name = (self.node or {}).get("metadata", {}).get("name")
        vmi = self._get_vmi(vmi_name) if vmi_name else None
        if not vmi:
            return None
        for iface in (vmi.get("spec") or {}).get("domain", {}).get("devices", {}).get(
            "interfaces"
        ) or []:
            if iface.get("name") == network_name and iface.get("macAddress"):
                return str(iface["macAddress"])
        return None

    def _ssh_root(self, script: str, timeout: int = 60) -> str:
        """Run bash on the guest via overlay SSH. sshd may lag the pod IP."""
        key = os.path.expanduser(str(self._ocp_cred.get("private_key_path") or "").strip())
        if not key or not os.path.isfile(key):
            raise NodeError(
                "ocpvirt-credentials private_key_path is required to configure "
                "the secondary UDN NIC in the guest"
            )
        ssh_ip = self.ssh_ip
        if not ssh_ip:
            raise NodeError("no overlay SSH IP for UDN guest configuration")
        cmd = [
            "ssh",
            "-i",
            key,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "LogLevel=ERROR",
            f"root@{ssh_ip}",
            "bash",
            "-s",
        ]
        last_err = ""
        deadline = IP_POLL_TIMEOUT
        for w in WaitUntil(timeout=deadline, interval=10):
            try:
                proc = subprocess.run(
                    cmd,
                    input=script,
                    text=True,
                    capture_output=True,
                    timeout=timeout,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                last_err = str(exc)
                continue
            if proc.returncode == 0:
                out = (proc.stdout or "").strip()
                if out:
                    LOG.info(out)
                return out
            last_err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            if ssh_guest_not_ready(last_err):
                if w._attempt == 1 or w._attempt % 3 == 0:
                    LOG.info(f"Waiting for guest SSH on {ssh_ip}: {last_err}")
                continue
            raise NodeError(
                f"guest UDN nmcli on {ssh_ip} failed: {last_err}"
            )
        raise NodeError(
            f"SSH to {ssh_ip} as root never succeeded for UDN nmcli: {last_err}"
        )

    def _ensure_guest_udn_ipv4(self, vm_name: str, network_name: str) -> None:
        """Apply the OVN-assigned UDN CIDR inside the guest (l2bridge does not).

        Do not trust VMI ``status.interfaces``: KubeVirt merges Multus CNI IPs
        into that list even when the guest NIC has no IPv4.
        """
        cidr = self._ovn_secondary_cidr(vm_name, network_name)
        mac = self._secondary_iface_mac(network_name)
        if not cidr or not mac:
            raise NodeError(
                f"VirtualMachine {vm_name} secondary UDN {network_name} has no "
                f"OVN CIDR or MAC (cidr={cidr} mac={mac})"
            )
        LOG.info(
            f"Configuring guest UDN {network_name} {cidr} mac={mac} on {vm_name}"
        )
        self._ssh_root(guest_udn_nmcli_script(mac, cidr))
        addr = str(ipaddress.ip_interface(cidr).ip)
        check = self._ssh_root(
            f"ip -4 -o addr show | grep -q 'inet {addr}/' && echo HAS_UDN_{addr}"
        )
        if f"HAS_UDN_{addr}" not in check:
            raise NodeError(
                f"VirtualMachine {vm_name} guest still missing {addr} after nmcli"
            )

    def _wait_until_udn_ip_known(
        self, vm_name: str, timeout: int = IP_POLL_TIMEOUT
    ) -> None:
        """Fail closed: secondary UDN must show a guest IPv4 before create returns."""
        for w in WaitUntil(timeout=timeout, interval=VM_POLL_INTERVAL):
            self.node = self._get_vm(vm_name) or self.node
            self._cached_ip = None
            ip = pick_vmi_udn_ip(
                self._vmi_interfaces(), udn=udn_network(self._ocp_cred)
            )
            if ip:
                LOG.info(f"VirtualMachine {vm_name} guest UDN IPv4 {ip}")
                self._cached_ip = ip
                return
        raise NodeError(
            f"VirtualMachine {vm_name} guest never got a UDN IPv4 in {timeout}s "
            "(l2bridge is L2-only; nmcli/cloud-init must configure the NIC)"
        )

    def _wait_until_vm_ready(
        self, vm_name: str, timeout: int = VM_POLL_TIMEOUT
    ) -> None:
        """Wait until VM printableStatus/Ready condition is True."""
        for w in WaitUntil(timeout=timeout, interval=VM_POLL_INTERVAL):
            vm = self._get_vm(vm_name)
            if not vm:
                if w._attempt == 1 or w._attempt % 6 == 0:
                    LOG.info(f"Waiting for VirtualMachine {vm_name}: not found yet")
                continue
            status = vm.get("status") or {}
            printable = status.get("printableStatus", "")
            ready = False
            for cond in status.get("conditions") or []:
                if cond.get("type") == "Ready" and cond.get("status") == "True":
                    ready = True
                    break
            if ready or printable == "Running":
                LOG.info(f"VirtualMachine {vm_name} is ready ({printable})")
                return
            if printable in (
                "ErrImagePull",
                "ImagePullBackOff",
                "ErrorPvcNotFound",
                "ErrorDataVolumeNotFound",
            ):
                raise NodeError(f"VirtualMachine {vm_name} failed: {printable}")
            if printable == "ErrorUnschedulable" and w.expired:
                raise NodeError(f"VirtualMachine {vm_name} failed: {printable}")
            if w._attempt == 1 or w._attempt % 6 == 0:
                LOG.info(
                    f"Waiting for VirtualMachine {vm_name}: status={printable or 'unknown'}"
                )
        if w.expired:
            raise NodeError(f"VirtualMachine {vm_name} not ready within {timeout}s")

    def _wait_until_ip_known(
        self, vm_name: str, timeout: int = IP_POLL_TIMEOUT
    ) -> None:
        """Poll VMI until an IPv4 address is assigned (fall back to any IP late)."""
        for w in WaitUntil(timeout=timeout, interval=VM_POLL_INTERVAL):
            # Refresh node so ip_address can read VMI
            self.node = self._get_vm(vm_name) or self.node
            ip = self._get_vmi_ip()
            if ip and ":" not in ip:
                LOG.info(f"VirtualMachine {vm_name} has IP {ip}")
                return
            # Keep waiting while only IPv6 is visible — DHCP IPv4 often arrives later.
            if ip:
                LOG.debug(f"VirtualMachine {vm_name} has IPv6 {ip}; waiting for IPv4")
        if w.expired:
            # Last chance: accept whatever IP is present
            self.node = self._get_vm(vm_name) or self.node
            ip = self._get_vmi_ip()
            if ip:
                LOG.warning(
                    f"VirtualMachine {vm_name} timed out waiting for IPv4; using {ip}"
                )
                return
            raise NodeError(f"VirtualMachine {vm_name} has no IP within {timeout}s")

    def _wait_until_vm_deleted(
        self, vm_name: str, timeout: int = VM_POLL_TIMEOUT
    ) -> None:
        for w in WaitUntil(timeout=timeout, interval=VM_POLL_INTERVAL):
            if self._get_vm(vm_name) is None:
                return
        if w.expired:
            raise NodeDeleteFailure(
                f"VirtualMachine {vm_name} still present after delete"
            )

    def _wait_until_vmi_phase(
        self,
        vm_name: str,
        phase: str,
        timeout: int = VM_POLL_TIMEOUT,
        allow_missing: bool = False,
    ) -> None:
        for w in WaitUntil(timeout=timeout, interval=VM_POLL_INTERVAL):
            vmi = self._get_vmi(vm_name)
            if vmi is None:
                if allow_missing:
                    return
                continue
            current = (vmi.get("status") or {}).get("phase")
            if current == phase:
                return
        if w.expired:
            raise NodeError(
                f"VMI {vm_name} did not reach phase {phase} within {timeout}s"
            )
