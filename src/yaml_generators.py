import base64
import ipaddress
import os
import re
from typing import Any, Dict, Optional, Tuple
from server_strategy import ServerType
import yaml
from config import bmh_logger


# ============================================================================
# BMC Credential Helper Functions
# ============================================================================

def get_bmc_credentials(vendor: str) -> Tuple[str, str]:
    """
    Get BMC credentials for a specific vendor from environment variables.

    Args:
        vendor: Vendor name (HP, DELL, or CISCO)

    Returns:
        Tuple of (username, password) in plain text

    Raises:
        ValueError: If credentials are not configured for the vendor
    """
    vendor_upper = vendor.upper()

    # Try vendor-specific credentials first, then fall back to default
    username = os.getenv('DEFAULT_IPMI_USERNAME')
    password = os.getenv('DEFAULT_IPMI_PASSWORD')
    vendor_name = vendor_upper

    if not username or not password:
        raise ValueError(
            f"Missing BMC credentials. "
            f"Please set DEFAULT_IPMI_USERNAME and DEFAULT_IPMI_PASSWORD environment variables"
        )

    return username, password


def get_bmc_address(vendor: str, ip_address: str) -> str:
    """
    Get vendor-specific BMC address format.

    These formats are static and do not change per deployment.

    Args:
        vendor: Vendor name (HP, DELL, or CISCO)
        ip_address: Management IP address

    Returns:
        Formatted BMC address string
    """
    vendor_upper = vendor.upper()

    if vendor_upper == "HP":
        return f"redfish-virtualmedia://{ip_address}/redfish/v1/Systems/1"
    elif vendor_upper == "DELL":
        return f"idrac-virtualmedia://{ip_address}/redfish/v1/Systems/System.Embedded.1"
    elif vendor_upper == "CISCO":
        return f"ipmi://{ip_address}:623"
    else:
        # Default to IPMI if vendor is unknown
        return f"ipmi://{ip_address}"


def get_secret_name(vendor: str, server_name: str) -> str:
    """
    Get vendor-specific secret name format.

    Format: {vendor}-cred-{server_name}

    Args:
        vendor: Vendor name (HP, DELL, or CISCO)
        server_name: Name of the server

    Returns:
        Formatted secret name (e.g., "hp-cred-server01")
    """
    vendor_lower = vendor.lower()

    if vendor_lower in ["hp", "dell", "cisco"]:
        return f"{vendor_lower}-cred-{server_name}"
    else:
        return f"bmc-cred-{server_name}"


class YamlGenerator:
    def __init__(self):
        self.bmh_logger = bmh_logger 
    
    def validate_inputs(self, mac: str, ip: str) -> None:
        """Validate MAC and IP address formats"""
        self.bmh_logger.debug(f"Validating inputs - MAC: {mac}, IP: {ip}")
        
        if not mac or not ip:
            self.bmh_logger.error("MAC address and/or IP address is empty")
            raise ValueError("MAC address and IP address must not be empty")

        MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")

        if not MAC_RE.fullmatch(mac):
            self.bmh_logger.error(f"Invalid MAC address format: {mac}")
            raise ValueError(f"Invalid MAC address format: {mac}")

        try:
            ipaddress.IPv4Address(ip)
            self.bmh_logger.debug(f"Successfully validated IP address: {ip}")
        except ipaddress.AddressValueError as exc:
            self.bmh_logger.error(f"Invalid IPv4 address: {ip} - {exc}")
            raise ValueError(f"Invalid IPv4 address: {ip}") from exc

        self.bmh_logger.info(f"Input validation successful for MAC: {mac}, IP: {ip}")


    def validate_yaml_format(self, data: Dict[str, Any]) -> None:
        """Validate that the generated data can be properly serialized to YAML format"""
        self.bmh_logger.debug("Validating YAML format of generated data")

        try:
            yaml.dump(data, default_flow_style=False)
            self.bmh_logger.debug("YAML validation successful")
        except yaml.YAMLError as exc:
            self.bmh_logger.error(f"YAML validation failed: {exc}")
            raise ValueError(f"Generated data cannot be converted to valid YAML: {exc}") from exc


    def generate_baremetal_host(
        self,
        name: str,
        namespace: str,
        server_vendor: str,
        mac_address: str,
        ipmi_address: str,
        infra_env: str,
        labels: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Generate BareMetalHost resource definition.

        Note: BMC credentials are stored in secrets and retrieved from config.py
        based on server_vendor. No need to pass username/password here.
        """
        self.bmh_logger.info(f"Generating BareMetalHost for {name} in namespace {namespace}")
        self.bmh_logger.debug(f"Parameters - MAC: {mac_address}, IPMI: {ipmi_address}, InfraEnv: {infra_env}")
        
        self.validate_inputs(mac_address, ipmi_address)

        # Get vendor-specific BMC address and secret name
        bmc_address = get_bmc_address(server_vendor, ipmi_address)
        secret_name = get_secret_name(server_vendor, name)
        
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
                "hardwareProfile": "empty",
                "customDeploy": {
                    "method": "start_assisted_install"
                },
                "automatedCleaningMode": "disabled",
                "bmc": {
                    "address": f"{bmc_address}",
                    "credentialsName": f"{secret_name}",
                    "disableCertificateVerification": True,
                },
                "bootMode": "UEFI",
            },
        }
        
        if labels:
            self.bmh_logger.debug(f"Additional labels applied: {labels}")
        
        self.validate_yaml_format(bmh_data)
        self.bmh_logger.info(f"Successfully generated BareMetalHost definition for {name}")
        
        return bmh_data


    def generate_bmc_secret(
        self,
        name: str,
        namespace: str,
        server_vendor: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate BMC Secret resource definition.

        Credentials are retrieved from environment variables:
        - DEFAULT_IPMI_USERNAME / DEFAULT_IPMI_PASSWORD for all servers

        Input credentials from environment are in plain text.
        Output secret data is base64 encoded for Kubernetes.

        Args:
            name: Server name
            namespace: Kubernetes namespace
            server_vendor: Vendor name (HP, DELL, CISCO)
            username: Optional BMC username override (uses env var if not provided)
            password: Optional BMC password override (uses env var if not provided)

        Returns:
            Secret resource dictionary with base64-encoded credentials

        Raises:
            ValueError: If BMC credentials are not configured for the vendor
        """
        self.bmh_logger.info(f"Generating BMC secret for {name} in namespace {namespace}")

        # Get vendor-specific credentials from environment if not provided
        if username is None or password is None:
            env_username, env_password = get_bmc_credentials(server_vendor)
            username = username or env_username
            password = password or env_password
            self.bmh_logger.debug(f"Using BMC credentials from environment for {server_vendor}")

        # Get vendor-specific secret name
        secret_name = get_secret_name(server_vendor, name)

        # Encode credentials to base64 for Kubernetes secret
        secret_data = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": secret_name, "namespace": namespace},
            "type": "Opaque",
            "data": {
                "username": base64.b64encode(username.encode()).decode(),
                "password": base64.b64encode(password.encode()).decode(),
            },
        }

        self.validate_yaml_format(secret_data)
        self.bmh_logger.info(f"Successfully generated BMC secret definition for {secret_name}")
        return secret_data
    
    def generate_nmstate_config(self, name: str, namespace: str, macAddress: str, infra_env: str, vlan_id: str) -> Dict[str, Any]:
        """Generate NMStateConfig resource definition"""
        self.bmh_logger.info(f"Generating NMStateConfig for {name} in namespace {namespace}")
        self.bmh_logger.info(f"MacAddress: {macAddress}")
        if "data" in name:
            interface_name = "ens2f0np0"
        else:
            interface_name = "eno12399np0"
        self.bmh_logger.info(f"Configuring the nmstateconfig with {interface_name}.{vlan_id}")
        nmstate_data = {
            "apiVersion": "nmstate.io/v1alpha1",
            "kind": "NMStateConfig",
            "metadata": {
                "labels": {
                    "infraenvs.agent-install.openshift.io": infra_env
                },
                "name": f"nmstate-config-{name}",
                "namespace": namespace
            },
            "spec": {
                "config": {
                    "interfaces": [
                        {
                            "ipv4": {
                                "enabled": False
                            },
                            "ipv6": {
                                "enabled": False
                            },
                            "macAddress": macAddress,
                            "name": f"{interface_name}",
                            "state": "up",
                            "type": "ethernet"
                        },
                        {
                            "ipv4":{
                                "dhcp": True,
                                "dhcp-client-id": "mac",
                                "enabled": True
                            },
                            "name": f"{interface_name}.{vlan_id}",
                            "state": "up",
                            "type": "vlan",
                            "vlan": {
                                "base-iface": f"{interface_name}",
                                "id": vlan_id
                            }
                        }
                    ]
                }
            },
            "interfaces": [
                {
                    "macAddress": macAddress,
                    "name": f"{interface_name}"
                }
            ]
        }
        self.validate_yaml_format(nmstate_data)
        self.bmh_logger.info(f"Successfully generated NMStateConfig definition for {name}")
        return nmstate_data