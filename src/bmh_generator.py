import re
import ipaddress
import base64
import yaml
from typing import Dict, Any, Optional


def validate_inputs(mac: str, ip: str) -> None:
    if not mac or not ip:
        raise ValueError("MAC address and IP address must not be empty")
    
    _MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
    
    if not _MAC_RE.fullmatch(mac):
        raise ValueError(f"Invalid MAC address format: {mac}")
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {ip}") from exc


def validate_yaml_format(data: Dict[str, Any]) -> None:
    """Validate that the generated data can be properly serialized to YAML format"""
    try:
        yaml.dump(data, default_flow_style=False)
    except yaml.YAMLError as exc:
        raise ValueError(f"Generated data cannot be converted to valid YAML: {exc}") from exc


def generate_baremetal_host(
    name: str,
    namespace: str,
    mac_address: str,
    ipmi_address: str,
    ipmi_username: str,
    ipmi_password: str,
    infra_env: str,
    labels: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:

    validate_inputs(mac_address, ipmi_address)

    bmh_data = {
        "apiVersion": "metal3.io/v1alpha1",
        "kind": "BareMetalHost",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "infraenvs.agent-install.openshift.io": infra_env,
                **(labels or {}),
            },
            "annotations": {
                "inspect.metal3.io": "disabled",
                "bmac.agent-install.openshift.io/hostname": name,
            },
        },
        "spec": {
            "online": True,
            "bootMACAddress": mac_address,
            "automatedCleaningMode": "disabled",
            "bmc": {
                "address": f"ipmi://{ipmi_address}",
                "credentialsName": f"{name}-bmc-secret",
                "disableCertificateVerification": True,
            },
            "bootMode": "UEFI",
        },
    }
    
    validate_yaml_format(bmh_data)
    return bmh_data


def generate_bmc_secret(
    name: str,
    namespace: str,
    username: str,
    password: str,
) -> Dict[str, Any]:
    secret_data = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": f"{name}-bmc-secret", "namespace": namespace},
        "type": "Opaque",
        "data": {
            "username": base64.b64encode(username.encode()).decode(),
            "password": base64.b64encode(password.encode()).decode(),
        },
    }
    
    validate_yaml_format(secret_data)
    return secret_data