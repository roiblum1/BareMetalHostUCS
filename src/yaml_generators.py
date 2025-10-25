import base64
import ipaddress
import re
from typing import Any, Dict, Optional

import yaml

from src.config import bmh_logger


def validate_inputs(mac: str, ip: str) -> None:
    """Validate MAC and IP address formats"""
    bmh_logger.debug(f"Validating inputs - MAC: {mac}, IP: {ip}")
    
    if not mac or not ip:
        bmh_logger.error("MAC address and/or IP address is empty")
        raise ValueError("MAC address and IP address must not be empty")
    
    MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
    
    if not MAC_RE.fullmatch(mac):
        bmh_logger.error(f"Invalid MAC address format: {mac}")
        raise ValueError(f"Invalid MAC address format: {mac}")
    
    try:
        ipaddress.IPv4Address(ip)
        bmh_logger.debug(f"Successfully validated IP address: {ip}")
    except ipaddress.AddressValueError as exc:
        bmh_logger.error(f"Invalid IPv4 address: {ip} - {exc}")
        raise ValueError(f"Invalid IPv4 address: {ip}") from exc
    
    bmh_logger.info(f"Input validation successful for MAC: {mac}, IP: {ip}")


def validate_yaml_format(data: Dict[str, Any]) -> None:
    """Validate that the generated data can be properly serialized to YAML format"""
    bmh_logger.debug("Validating YAML format of generated data")
    
    try:
        yaml.dump(data, default_flow_style=False)
        bmh_logger.debug("YAML validation successful")
    except yaml.YAMLError as exc:
        bmh_logger.error(f"YAML validation failed: {exc}")
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
    """Generate BareMetalHost resource definition"""
    bmh_logger.info(f"Generating BareMetalHost for {name} in namespace {namespace}")
    bmh_logger.debug(f"Parameters - MAC: {mac_address}, IPMI: {ipmi_address}, InfraEnv: {infra_env}")
    
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
    
    if labels:
        bmh_logger.debug(f"Additional labels applied: {labels}")
    
    validate_yaml_format(bmh_data)
    bmh_logger.info(f"Successfully generated BareMetalHost definition for {name}")
    
    return bmh_data


def generate_bmc_secret(
    name: str,
    namespace: str,
    username: str,
    password: str,
) -> Dict[str, Any]:
    """Generate BMC Secret resource definition"""
    bmh_logger.info(f"Generating BMC secret for {name} in namespace {namespace}")
    bmh_logger.debug(f"BMC username: {username}")
    
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
    bmh_logger.info(f"Successfully generated BMC secret definition for {name}-bmc-secret")
    
    return secret_data