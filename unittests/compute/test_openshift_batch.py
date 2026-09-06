from unittest.mock import MagicMock, patch

import pytest

from compute.exceptions import NodeError
from compute.openshift import (
    DEFAULT_OCPVIRT_PROFILE,
    KUBEVIRT_CLUSTER_INSTANCETYPE_KIND,
    apply_ocpvirt_vm_profile,
    build_virtualmachine_cr,
    datavolume_names_from_vm,
    guest_udn_nmcli_script,
    load_ocpvirt_namespace_config,
    parse_ovn_secondary_cidr,
    ssh_guest_not_ready,
    pick_vmi_ssh_ip,
    pick_vmi_udn_ip,
    process_ocpvirt_custom_config,
    resolve_ocpvirt_credentials,
    resolve_ocpvirt_image_name,
    resolve_ocpvirt_instancetype,
    validate_ocpvirt_credentials,
    validate_ocpvirt_inventory,
    validate_ocpvirt_namespace_config,
    validate_precreated_volume_names,
)

AUTH_OSP_CRED = {
    "globals": {
        "ocpvirt-credentials": {
            "token": "secret",
            "private_key_path": "/home/jenkins/.ssh/id_ed25519",
        }
    }
}

OCP_CRED = {
    "server": "https://api.example:6443",
    "token": "secret",
    "namespace": "ceph-jenkins--runtime-int",
    "storage_class": "rh-restricted-nfs",
    "network": "bridge-504",
    "datasources": {
        "rhel9": "datasource://openshift-virtualization-os-images/rhel9",
        "rhel10": "datasource://openshift-virtualization-os-images/rhel10",
    },
}

CLUSTER_INSTANCE_TYPES = ["o1.large", "cx1.large", "cx1.2xlarge", "cx1.4xlarge"]


def _mock_custom_api():
    api = MagicMock()
    api.list_cluster_custom_object.return_value = {
        "items": [{"metadata": {"name": name}} for name in CLUSTER_INSTANCE_TYPES]
    }
    return api


def test_process_ocpvirt_custom_config_defaults():
    cfg = process_ocpvirt_custom_config(None)
    assert cfg == {
        "pvc_batch_size": 3,
        "vm_batch_size": 1,
        "ocpvirt_profile": DEFAULT_OCPVIRT_PROFILE,
    }
    assert DEFAULT_OCPVIRT_PROFILE == "o1.large"


def test_process_ocpvirt_custom_config_overrides():
    cfg = process_ocpvirt_custom_config(
        [
            "pvc_batch_size=5",
            "vm_batch_size=2",
            "ocpvirt_namespace=rdu3_ceph_jenkins",
            "ocpvirt_profile=cx1.2xlarge",
            "ibm-build=True",
        ]
    )
    assert cfg == {
        "pvc_batch_size": 5,
        "vm_batch_size": 2,
        "ocpvirt_profile": "cx1.2xlarge",
    }


@patch("compute.openshift.get_k8s_clients")
def test_apply_ocpvirt_vm_profile_uses_cluster_instancetype(mock_clients):
    mock_clients.return_value = (_mock_custom_api(), MagicMock())
    params = apply_ocpvirt_vm_profile(
        {"image-name": "datasource://rhel9"},
        OCP_CRED,
        ["ocpvirt_profile=cx1.2xlarge"],
    )
    assert params["instancetype"] == "cx1.2xlarge"
    assert params["image-name"] == "datasource://rhel9"


@patch("compute.openshift.get_k8s_clients")
def test_apply_ocpvirt_vm_profile_defaults_to_o1_large(mock_clients):
    mock_clients.return_value = (_mock_custom_api(), MagicMock())
    params = apply_ocpvirt_vm_profile(
        {"image-name": "datasource://rhel9"},
        OCP_CRED,
        None,
    )
    assert params["instancetype"] == "o1.large"


@patch(
    "compute.openshift.list_cluster_instancetypes", return_value=CLUSTER_INSTANCE_TYPES
)
def test_resolve_ocpvirt_instancetype_unknown(mock_list):
    with pytest.raises(NodeError, match="Unknown ocpvirt_profile"):
        resolve_ocpvirt_instancetype(MagicMock(), "missing")


def test_build_virtualmachine_cr_with_instancetype():
    vm = build_virtualmachine_cr(
        node_name="ceph-test-node",
        namespace="test-ns",
        image_name="https://example.com/disk.qcow2",
        storage_class="nfs",
        network="bridge-504",
        root_disk_size="80Gi",
        instancetype_name="cx1.2xlarge",
        precreated_volume_names=[],
    )
    assert vm["spec"]["instancetype"] == {
        "kind": KUBEVIRT_CLUSTER_INSTANCETYPE_KIND,
        "name": "cx1.2xlarge",
    }
    domain = vm["spec"]["template"]["spec"]["domain"]
    assert "cpu" not in domain
    assert "resources" not in domain


def test_build_virtualmachine_cr_requires_instancetype():
    with pytest.raises(NodeError, match="instancetype_name is required"):
        build_virtualmachine_cr(
            node_name="ceph-test-node",
            namespace="test-ns",
            image_name="https://example.com/disk.qcow2",
            storage_class="nfs",
            network="bridge-504",
            root_disk_size="80Gi",
            instancetype_name="",
            precreated_volume_names=[],
        )


def test_validate_ocpvirt_credentials_auth_only():
    cred = validate_ocpvirt_credentials(AUTH_OSP_CRED)
    assert cred["token"] == "secret"
    assert "server" not in cred


def test_validate_ocpvirt_namespace_config_requires_server():
    with pytest.raises(NodeError, match="server is required"):
        validate_ocpvirt_namespace_config({"namespace": "ns", "storage_class": "nfs"})


def test_resolve_ocpvirt_image_name_short_name():
    resolved = resolve_ocpvirt_image_name("datasource://rhel9", OCP_CRED)
    assert resolved == "datasource://openshift-virtualization-os-images/rhel9"


def test_load_ocpvirt_namespace_config():
    cfg = load_ocpvirt_namespace_config(["ocpvirt_namespace=rdu3_ceph_jenkins"])
    assert cfg["server"] == "https://10.5.229.33:6443"
    assert "instance_types" not in cfg


def test_resolve_ocpvirt_credentials():
    merged = resolve_ocpvirt_credentials(
        AUTH_OSP_CRED, ["ocpvirt_namespace=rdu3_ceph_jenkins"]
    )
    assert merged["token"] == "secret"
    assert merged["server"] == "https://10.5.229.33:6443"


def test_validate_ocpvirt_inventory_resolves_datasource():
    params = validate_ocpvirt_inventory(
        inventory={
            "instance": {
                "setup": "#cloud-config\n",
                "create": {"image-name": "datasource://rhel9"},
            }
        },
        ceph_cluster={"name": "ceph"},
        ocp_cred=OCP_CRED,
    )
    assert (
        params["image-name"] == "datasource://openshift-virtualization-os-images/rhel9"
    )
    assert "cpu" not in params
    assert "memory" not in params


def test_validate_precreated_volume_names_rejects_none():
    with pytest.raises(NodeError, match="precreated_volume_names is required"):
        validate_precreated_volume_names(None)


def test_build_virtualmachine_cr_requires_precreated_volume_names():
    with pytest.raises(NodeError, match="precreated_volume_names is required"):
        build_virtualmachine_cr(
            node_name="ceph-test-node",
            namespace="test-ns",
            image_name="https://example.com/disk.qcow2",
            storage_class="nfs",
            network="bridge-504",
            root_disk_size="80Gi",
            instancetype_name="o1.large",
        )


def test_build_virtualmachine_cr_secondary_udn():
    vm = build_virtualmachine_cr(
        node_name="ceph-test-node",
        namespace="test-ns",
        image_name="https://example.com/disk.qcow2",
        storage_class="nfs",
        network="default",
        root_disk_size="80Gi",
        instancetype_name="o1.large",
        precreated_volume_names=[],
        secondary_network="ceph-public",
    )
    spec = vm["spec"]["template"]["spec"]
    assert spec["domain"]["devices"]["interfaces"] == [
        {"name": "default", "masquerade": {}},
        {"name": "ceph-public", "binding": {"name": "l2bridge"}},
    ]
    assert spec["networks"] == [
        {"name": "default", "pod": {}},
        {"name": "ceph-public", "multus": {"networkName": "ceph-public"}},
    ]


def test_pick_vmi_ssh_ip_skips_udn():
    ip = pick_vmi_ssh_ip(
        [
            {"name": "ceph-public", "ipAddress": "192.168.0.10"},
            {"name": "default", "ipAddress": "172.19.8.20"},
        ]
    )
    assert ip == "172.19.8.20"


def test_pick_vmi_udn_ip_prefers_guest_udn():
    ip = pick_vmi_udn_ip(
        [
            {"name": "default", "ipAddress": "172.19.83.39"},
            {
                "name": "ceph-public",
                "ipAddress": "192.168.0.1",
                "ipAddresses": ["192.168.0.1", "fe80::2d:d0ff:fe40:d876"],
            },
        ]
    )
    assert ip == "192.168.0.1"


def test_pick_vmi_udn_ip_none_without_guest_ipv4():
    ip = pick_vmi_udn_ip(
        [
            {"name": "default", "ipAddress": "172.19.83.39"},
            {
                "name": "ceph-public",
                "ipAddress": "fe80::2d:d0ff:fe40:d876",
                "ipAddresses": ["fe80::2d:d0ff:fe40:d876"],
            },
        ]
    )
    assert ip is None


def test_parse_ovn_secondary_cidr_from_pod_annotation():
    annotation = (
        '{"ceph-teuthology--runtime-int/ceph-public":{"ip_addresses":'
        '["192.168.0.1/20"],"mac_address":"02:2d:d0:40:d8:76",'
        '"ip_address":"192.168.0.1/20","role":"secondary"},'
        '"default":{"ip_address":"172.19.83.39/20","role":"primary"}}'
    )
    assert (
        parse_ovn_secondary_cidr(
            annotation, "ceph-teuthology--runtime-int", "ceph-public"
        )
        == "192.168.0.1/20"
    )


def test_guest_udn_nmcli_script_contains_ovn_cidr():
    script = guest_udn_nmcli_script("02:2D:D0:40:D8:76", "192.168.0.1/20")
    assert "MAC=02:2d:d0:40:d8:76" in script
    assert "CIDR=192.168.0.1/20" in script
    assert "ipv4.never-default yes" in script
    assert "con-name ceph-public" in script


def test_datavolume_names_from_vm_includes_root_and_precreated():
    vm = build_virtualmachine_cr(
        node_name="ceph-test-node",
        namespace="test-ns",
        image_name="https://example.com/disk.qcow2",
        storage_class="nfs",
        network="bridge-504",
        root_disk_size="80Gi",
        instancetype_name="o1.large",
        precreated_volume_names=["ceph-test-node-vol-0", "ceph-test-node-vol-1"],
    )
    names = datavolume_names_from_vm(vm)
    assert "ceph-test-node-root" in names
    assert "ceph-test-node-vol-0" in names
    assert "ceph-test-node-vol-1" in names


def test_ssh_guest_not_ready_retries_overlay_gaps():
    assert ssh_guest_not_ready(
        "ssh: connect to host 172.18.79.156 port 22: No route to host"
    )
    assert ssh_guest_not_ready("Connection refused")
    assert ssh_guest_not_ready("Connection timed out")
    assert not ssh_guest_not_ready("Permission denied (publickey)")
    assert not ssh_guest_not_ready("guest UDN nmcli failed: no guest NIC")
