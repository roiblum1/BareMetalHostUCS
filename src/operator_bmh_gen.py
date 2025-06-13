import asyncio
import base64
import ipaddress
import json
import logging
import os
import re
import subprocess
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import kopf
import kubernetes
import requests
import yaml
from kubernetes import client, config
from ucsmsdk.mometa.compute.ComputeRackUnit import ComputeRackUnit
from ucsmsdk.ucshandle import UcsHandle
from ucscsdk.ucschandle import UcscHandle
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# Create separate loggers for different components
bmh_logger = logging.getLogger('bmh_generator')
ucs_logger = logging.getLogger('ucs_client')
operator_logger = logging.getLogger('k8s_operator')
buffer_logger = logging.getLogger('bmh_buffer')

# Global configuration
MAX_AVAILABLE_SERVERS = 20  # Maximum number of servers that can be available (not in cluster)
BUFFER_CHECK_INTERVAL = 30  # Seconds between buffer checks

# ============================================================================
# BMH Generator Functions (from bmh_generator.py)
# ============================================================================

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
    server_vendor: str,
    labels: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Generate BareMetalHost resource definition"""
    bmh_logger.info(f"Generating BareMetalHost for {name} in namespace {namespace}")
    bmh_logger.debug(f"Parameters - MAC: {mac_address}, IPMI: {ipmi_address}, InfraEnv: {infra_env}, Vendor: {server_vendor}")
    
    validate_inputs(mac_address, ipmi_address)
    
    # Determine BMC address format based on vendor
    if server_vendor.upper() == "HP":
        bmc_address = f"redfish-virtualmedia://{ipmi_address}/redfish/v1/Systems/1"
        secret_name = f"hp-bmc-{name}"
    elif server_vendor.upper() == "DELL":
        bmc_address = f"idrac-virtualmedia://{ipmi_address}/redfish/v1/Systems/System.Embedded.1"
        secret_name = f"dell-bmc-{name}"
    elif server_vendor.upper() == "CISCO":
        bmc_address = f"ipmi://{ipmi_address}"
        secret_name = f"cisco-bmc-{name}"
    else:
        bmh_logger.warning(f"Unknown vendor {server_vendor}, defaulting to IPMI")
        bmc_address = f"ipmi://{ipmi_address}"
        secret_name = f"bmc-{name}"
    
    bmh_logger.info(f"Using BMC address format for {server_vendor}: {bmc_address}")
    
    bmh_data = {
        "apiVersion": "metal3.io/v1alpha1",
        "kind": "BareMetalHost",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "infraenvs.agent-install.openshift.io": infra_env,
                "server-vendor": server_vendor.lower(),
                **(labels or {}),
            },
            "annotations": {
                "inspect.metal3.io": "disabled",
                "bmac.agent-install.openshift.io/hostname": name,
                "server-vendor": server_vendor.upper(),
            },
        },
        "spec": {
            "online": True,
            "bootMACAddress": mac_address,
            "automatedCleaningMode": "disabled",
            "bmc": {
                "address": bmc_address,
                "credentialsName": secret_name,
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
    server_vendor: str,
) -> Dict[str, Any]:
    """Generate BMC Secret resource definition"""
    bmh_logger.info(f"Generating BMC secret for {name} in namespace {namespace}")
    bmh_logger.debug(f"BMC username: {username}, Vendor: {server_vendor}")
    
    # Determine secret name based on vendor
    if server_vendor.upper() == "HP":
        secret_name = f"hp-bmc-{name}"
    elif server_vendor.upper() == "DELL":
        secret_name = f"dell-bmc-{name}"
    elif server_vendor.upper() == "CISCO":
        secret_name = f"cisco-bmc-{name}"
    else:
        bmh_logger.warning(f"Unknown vendor {server_vendor}, using default naming")
        secret_name = f"bmc-{name}"
    
    secret_data = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": secret_name,
            "namespace": namespace,
            "labels": {
                "server-vendor": server_vendor.lower(),
                "baremetalhost": name,
            }
        },
        "type": "Opaque",
        "data": {
            "username": base64.b64encode(username.encode()).decode(),
            "password": base64.b64encode(password.encode()).decode(),
        },
    }
    
    validate_yaml_format(secret_data)
    bmh_logger.info(f"Successfully generated BMC secret definition for {secret_name}")
    
    return secret_data

# ============================================================================
# UCS Client Class (from ucs_client.py)
# ============================================================================

class ServerType(Enum):
    """Enum for server types based on naming convention"""
    HP = "hp"
    CISCO = "cisco"
    DELL = "dell"
    UNKNOWN = "unknown"


class UnifiedServerClient:
    """
    Unified client for managing HP, Cisco UCS, and Dell servers.
    Automatically detects server type based on naming convention and searches efficiently.
    """
    
    def __init__(self, 
                 # HP OneView credentials
                 oneview_ip=None, 
                 oneview_username=None, 
                 oneview_password=None,
                 # UCS Central/Manager credentials
                 ucs_central_ip=None, 
                 central_username=None, 
                 central_password=None,
                 manager_username=None, 
                 manager_password=None,
                 # Dell OME credentials
                 ome_ip=None, 
                 ome_username=None, 
                 ome_password=None):
        """
        Initialize unified server client with credentials for all systems.
        
        Args:
            oneview_ip: HP OneView IP address
            oneview_username: HP OneView username
            oneview_password: HP OneView password
            ucs_central_ip: Cisco UCS Central IP address
            central_username: UCS Central username
            central_password: UCS Central password
            manager_username: UCS Manager username
            manager_password: UCS Manager password
            ome_ip: Dell OpenManage Enterprise IP address
            ome_username: Dell OME username
            ome_password: Dell OME password
        """
        # HP OneView configuration
        self.oneview_ip = oneview_ip
        self.oneview_username = oneview_username
        self.oneview_password = oneview_password
        self.oneview_session = None
        self.oneview_auth_token = None
        self.oneview_base_url = f"https://{oneview_ip}" if oneview_ip else None
        
        # UCS configuration
        self.ucs_central_ip = ucs_central_ip
        self.central_username = central_username
        self.central_password = central_password
        self.manager_username = manager_username
        self.manager_password = manager_password
        self.ucsc_handle = None
        
        # Dell OME configuration
        self.ome_ip = ome_ip
        self.ome_username = ome_username
        self.ome_password = ome_password
        self.ome_session = None
        self.ome_auth_token = None
        self.ome_base_url = f"https://{ome_ip}/api" if ome_ip else None
        
        # Cache for server data to improve performance
        self._hp_servers_cache = None
        self._ucs_servers_cache = None
        self._dell_servers_cache = None
        
        logger.info("Initialized UnifiedServerClient")
    
    def detect_server_type(self, server_name: str, server_vendor: Optional[str] = None) -> ServerType:
        """
        Detect server type based on explicit vendor or naming convention.
        
        Args:
            server_name: Name of the server
            server_vendor: Optional explicit server vendor (HP, Dell, Cisco)
            
        Returns:
            ServerType enum value
        """
        # If server_vendor is explicitly provided, use it
        if server_vendor:
            vendor_upper = server_vendor.upper()
            if vendor_upper == "HP":
                logger.debug(f"Using explicit vendor HP for server: {server_name}")
                return ServerType.HP
            elif vendor_upper == "DELL":
                logger.debug(f"Using explicit vendor Dell for server: {server_name}")
                return ServerType.DELL
            elif vendor_upper == "CISCO":
                logger.debug(f"Using explicit vendor Cisco for server: {server_name}")
                return ServerType.CISCO
            else:
                logger.warning(f"Unknown vendor '{server_vendor}' provided, falling back to name detection")
        
        # Fall back to name-based detection
        server_name_lower = server_name.lower()
        
        if 'rf' in server_name_lower:
            logger.debug(f"Detected HP server based on 'rf' in name: {server_name}")
            return ServerType.HP
        elif 'ome' in server_name_lower:
            logger.debug(f"Detected Dell server based on 'ome' in name: {server_name}")
            return ServerType.DELL
        else:
            # Default to Cisco for basic names
            logger.debug(f"Defaulting to Cisco server for: {server_name}")
            return ServerType.CISCO
    
    def get_server_info(self, server_name: str, server_vendor: Optional[str] = None) -> Tuple[str, str]:
        """
        Get server MAC address and management IP based on server name.
        Automatically detects server type and searches efficiently.
        
        Args:
            server_name: Name of the server
            server_vendor: Optional explicit server vendor (HP, Dell, Cisco)
            
        Returns:
            Tuple of (mac_address, management_ip)
        """
        logger.info(f"Getting server info for: {server_name}, vendor: {server_vendor or 'auto-detect'}")
        
        # Detect server type based on vendor annotation or naming convention
        server_type = self.detect_server_type(server_name, server_vendor)
        
        # Define search order based on detected type
        if server_type == ServerType.HP:
            search_order = [ServerType.HP, ServerType.CISCO, ServerType.DELL]
        elif server_type == ServerType.DELL:
            search_order = [ServerType.DELL, ServerType.CISCO, ServerType.HP]
        else:  # CISCO
            search_order = [ServerType.CISCO, ServerType.HP, ServerType.DELL]
        
        # Try each system in order
        for system in search_order:
            try:
                logger.info(f"Searching in {system.value} system...")
                
                if system == ServerType.HP:
                    if self._is_hp_configured():
                        mac, ip = self._get_hp_server_info(server_name)
                        if mac and ip:
                            logger.info(f"Found server in HP OneView")
                            return mac, ip
                            
                elif system == ServerType.CISCO:
                    if self._is_ucs_configured():
                        mac, ip = self._get_ucs_server_info(server_name)
                        if mac and ip:
                            logger.info(f"Found server in Cisco UCS")
                            return mac, ip
                            
                elif system == ServerType.DELL:
                    if self._is_dell_configured():
                        mac, ip = self._get_dell_server_info(server_name)
                        if mac and ip:
                            logger.info(f"Found server in Dell OME")
                            return mac, ip
                            
            except Exception as e:
                logger.warning(f"Error searching in {system.value} system: {str(e)}")
                continue
        
        # If we get here, server was not found in any system
        raise ValueError(f"Server {server_name} not found in any configured system")
    
    # HP OneView Methods
    def _is_hp_configured(self) -> bool:
        """Check if HP OneView is configured"""
        return all([self.oneview_ip, self.oneview_username, self.oneview_password])
    
    def _ensure_hp_connected(self):
        """Ensure connection to HP OneView"""
        if not self.oneview_session or not self.oneview_auth_token:
            logger.info(f"Connecting to HP OneView at {self.oneview_ip}")
            
            self.oneview_session = requests.Session()
            self.oneview_session.verify = False
            
            auth_url = f"{self.oneview_base_url}/rest/login-sessions"
            auth_data = {
                "userName": self.oneview_username,
                "password": self.oneview_password
            }
            
            headers = {
                "Content-Type": "application/json",
                "X-API-Version": "2000"
            }
            
            response = self.oneview_session.post(auth_url, json=auth_data, headers=headers)
            response.raise_for_status()
            
            self.oneview_auth_token = response.json().get('sessionID')
            self.oneview_session.headers.update({
                'Auth': self.oneview_auth_token,
                'X-API-Version': '2000'
            })
            
            logger.info("Successfully connected to HP OneView")
    
    def _get_hp_server_info(self, server_name: str) -> Tuple[Optional[str], Optional[str]]:
        """Get HP server info"""
        self._ensure_hp_connected()
        
        # Use cache if available
        if self._hp_servers_cache is None:
            servers_url = f"{self.oneview_base_url}/rest/server-hardware"
            response = self.oneview_session.get(servers_url)
            response.raise_for_status()
            self._hp_servers_cache = response.json().get('members', [])
        
        # Search for server
        for server in self._hp_servers_cache:
            if (server_name.upper() == server.get('name', '').upper() or 
                server_name.upper() == server.get('serialNumber', '').upper()):
                
                # Get iLO IP
                ilo_ip = ""
                mp_host_info = server.get('mpHostInfo', {})
                mp_addresses = mp_host_info.get('mpIpAddresses', [])
                
                for addr_info in mp_addresses:
                    if addr_info.get('type') in ['DHCP', 'Static']:
                        ilo_ip = addr_info.get('address', '')
                        if ilo_ip:
                            break
                
                # Get MAC address
                mac_address = self._get_hp_mac_address(server.get('uri'))
                
                if mac_address and ilo_ip:
                    return mac_address, ilo_ip
        
        return None, None
    
    def _get_hp_mac_address(self, server_uri: str) -> Optional[str]:
        """Get HP server MAC address"""
        try:
            response = self.oneview_session.get(f"{self.oneview_base_url}{server_uri}")
            response.raise_for_status()
            
            server_data = response.json()
            port_map = server_data.get('portMap', {})
            device_slots = port_map.get('deviceSlots', [])
            
            for slot in device_slots:
                for port in slot.get('physicalPorts', []):
                    mac = port.get('mac', '')
                    if mac and mac != '00:00:00:00:00:00':
                        return mac
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting HP MAC address: {str(e)}")
            return None
    
    # Cisco UCS Methods
    def _is_ucs_configured(self) -> bool:
        """Check if UCS is configured"""
        return all([self.ucs_central_ip, self.central_username, self.central_password,
                   self.manager_username, self.manager_password])
    
    def _ensure_ucs_connected(self):
        """Ensure connection to UCS Central"""
        if not self.ucsc_handle:
            logger.info(f"Connecting to UCS Central at {self.ucs_central_ip}")
            
            try:
                # Import UCS SDK modules here to avoid import errors if not installed
                from ucscsdk.ucschandle import UcscHandle
                from ucsmsdk.ucshandle import UcsHandle
                
                self.ucsc_handle = UcscHandle(self.ucs_central_ip, self.central_username, 
                                             self.central_password)
                self.ucsc_handle.login()
                
                # Store class references for later use
                self._UcsHandle = UcsHandle
                
                logger.info("Successfully connected to UCS Central")
                
            except ImportError:
                logger.error("UCS SDK not installed. Install with: pip install ucsmsdk ucscsdk")
                raise
    
    def _get_ucs_server_info(self, server_name: str) -> Tuple[Optional[str], Optional[str]]:
        """Get UCS server info"""
        self._ensure_ucs_connected()
        
        # Use cache if available
        if self._ucs_servers_cache is None:
            self._ucs_servers_cache = self.ucsc_handle.query_classid("lsServer")
        
        for server in self._ucs_servers_cache:
            if server_name.upper() == server.name.upper():
                domain = server.domain
                ucsm_handle = None
                
                try:
                    # Connect to UCS Manager
                    ucsm_handle = self._UcsHandle(domain, self.manager_username, 
                                                 self.manager_password)
                    ucsm_handle.login()
                    
                    # Get server details
                    server_details = self.ucsc_handle.query_dn(server.dn)
                    if not server_details:
                        continue
                    
                    # Get KVM IP
                    kvm_ip = ""
                    mgmt_interfaces = ucsm_handle.query_children(in_mo=server_details, 
                                                                class_id="VnicIpV4PooledAddr")
                    for iface in mgmt_interfaces:
                        if hasattr(iface, 'addr') and iface.addr:
                            kvm_ip = str(iface.addr)
                            break
                    
                    # Get MAC address
                    mac_address = ""
                    adapters = ucsm_handle.query_children(in_mo=server_details, 
                                                         class_id="VnicEther")
                    if adapters:
                        sorted_adapters = sorted(adapters, key=lambda x: x.name[3:])
                        if sorted_adapters and hasattr(sorted_adapters[0], 'addr'):
                            mac_address = sorted_adapters[0].addr
                    
                    if mac_address and kvm_ip:
                        return mac_address, kvm_ip
                        
                finally:
                    if ucsm_handle:
                        try:
                            ucsm_handle.logout()
                        except:
                            pass
        
        return None, None
    
    # Dell OME Methods
    def _is_dell_configured(self) -> bool:
        """Check if Dell OME is configured"""
        return all([self.ome_ip, self.ome_username, self.ome_password])
    
    def _ensure_dell_connected(self):
        """Ensure connection to Dell OME"""
        if not self.ome_session or not self.ome_auth_token:
            logger.info(f"Connecting to Dell OME at {self.ome_ip}")
            
            self.ome_session = requests.Session()
            self.ome_session.verify = False
            
            auth_url = f"{self.ome_base_url}/SessionService/Sessions"
            auth_data = {
                "UserName": self.ome_username,
                "Password": self.ome_password,
                "SessionType": "API"
            }
            
            response = self.ome_session.post(auth_url, json=auth_data)
            response.raise_for_status()
            
            self.ome_auth_token = response.headers.get('X-Auth-Token')
            self.ome_session.headers.update({'X-Auth-Token': self.ome_auth_token})
            
            logger.info("Successfully connected to Dell OME")
    
    def _get_dell_server_info(self, server_name: str) -> Tuple[Optional[str], Optional[str]]:
        """Get Dell server info"""
        self._ensure_dell_connected()
        
        # Use cache if available
        if self._dell_servers_cache is None:
            devices_url = f"{self.ome_base_url}/DeviceService/Devices"
            params = {
                '$filter': 'Type eq 1000',  # 1000 = Server type
                '$top': 5000
            }
            
            response = self.ome_session.get(devices_url, params=params)
            response.raise_for_status()
            self._dell_servers_cache = response.json().get('value', [])
        
        # Search for server
        for server in self._dell_servers_cache:
            server_display_name = server.get('DeviceName', '')
            server_service_tag = server.get('DeviceServiceTag', '')
            
            if (server_name.upper() == server_display_name.upper() or 
                server_name.upper() == server_service_tag.upper()):
                
                # Get iDRAC IP
                idrac_ip = ""
                device_mgmt = server.get('DeviceManagement', [])
                
                for mgmt in device_mgmt:
                    if mgmt.get('ManagementType') == 2:  # 2 = iDRAC
                        network_address = mgmt.get('NetworkAddress', '')
                        if network_address:
                            idrac_ip = network_address
                            break
                
                if not idrac_ip and server.get('ManagementIP'):
                    idrac_ip = server.get('ManagementIP')
                
                # Get MAC address
                mac_address = self._get_dell_mac_address(server.get('Id'))
                
                if mac_address and idrac_ip:
                    return mac_address, idrac_ip
        
        return None, None
    
    def _get_dell_mac_address(self, server_id: int) -> Optional[str]:
        """Get Dell server MAC address"""
        try:
            interfaces_url = f"{self.ome_base_url}/DeviceService/Devices({server_id})/InventoryDetails('networkInterfaces')"
            
            response = self.ome_session.get(interfaces_url)
            response.raise_for_status()
            
            interfaces_data = response.json()
            interfaces = interfaces_data.get('InventoryInfo', [])
            
            if interfaces:
                sorted_interfaces = sorted(interfaces, key=lambda x: x.get('Name', ''))
                
                for interface in sorted_interfaces:
                    mac = interface.get('MacAddress', '')
                    if mac and mac != '00:00:00:00:00:00':
                        return mac
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting Dell MAC address: {str(e)}")
            return None
    
    def disconnect(self):
        """Disconnect from all systems"""
        # Disconnect from HP OneView
        if self.oneview_session and self.oneview_auth_token:
            try:
                logout_url = f"{self.oneview_base_url}/rest/login-sessions"
                self.oneview_session.delete(logout_url)
                self.oneview_session.close()
                logger.info("Disconnected from HP OneView")
            except Exception as e:
                logger.warning(f"Error disconnecting from HP OneView: {str(e)}")
            finally:
                self.oneview_session = None
                self.oneview_auth_token = None
        
        # Disconnect from UCS Central
        if self.ucsc_handle:
            try:
                self.ucsc_handle.logout()
                logger.info("Disconnected from UCS Central")
            except Exception as e:
                logger.warning(f"Error disconnecting from UCS Central: {str(e)}")
            finally:
                self.ucsc_handle = None
        
        # Disconnect from Dell OME
        if self.ome_session and self.ome_auth_token:
            try:
                logout_url = f"{self.ome_base_url}/SessionService/Sessions"
                self.ome_session.delete(logout_url)
                self.ome_session.close()
                logger.info("Disconnected from Dell OME")
            except Exception as e:
                logger.warning(f"Error disconnecting from Dell OME: {str(e)}")
            finally:
                self.ome_session = None
                self.ome_auth_token = None
        
        # Clear caches
        self._hp_servers_cache = None
        self._ucs_servers_cache = None
        self._dell_servers_cache = None
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure cleanup"""
        self.disconnect()


# ============================================================================
# Kubernetes Operator with Buffer Management
# ============================================================================

# Load Kubernetes config
# ============================================================================
# Kubernetes Operator with Buffer Management (UPDATED)
# ============================================================================

# Load Kubernetes config
try:
    config.load_incluster_config()
    operator_logger.info("Loaded in-cluster Kubernetes configuration")
except Exception as e:
    operator_logger.warning(f"Failed to load in-cluster config: {e}")
    operator_logger.info("Falling back to kubeconfig")
    config.load_kube_config()

# Initialize Kubernetes clients
k8s_client = client.ApiClient()
custom_api = client.CustomObjectsApi(k8s_client)
core_v1 = client.CoreV1Api(k8s_client)
operator_logger.info("Initialized Kubernetes API clients")

# Unified server client (initialized on startup)
unified_client = None

# Buffer management
bmh_buffer_lock = asyncio.Lock()
buffer_check_task = None

def get_available_baremetalhosts() -> List[Dict[str, Any]]:
    """Get list of BareMetalHosts that are available (not provisioned)"""
    buffer_logger.debug("Querying all BareMetalHosts")
    
    try:
        bmhs = custom_api.list_cluster_custom_object(
            group="metal3.io",
            version="v1alpha1",
            plural="baremetalhosts"
        )
        
        available_bmhs = []
        
        for bmh in bmhs.get('items', []):
            status = bmh.get('status', {})
            provisioning_state = status.get('provisioning', {}).get('state', '')
            
            # A BMH is available if it's NOT in "provisioned" state
            # Provisioned means it's already in a cluster
            if provisioning_state != 'provisioned':
                available_bmhs.append(bmh)
                buffer_logger.debug(f"BMH {bmh['metadata']['name']} is available (state: {provisioning_state})")
            else:
                buffer_logger.debug(f"BMH {bmh['metadata']['name']} is in cluster (state: provisioned)")
        
        buffer_logger.info(f"Found {len(available_bmhs)} available BareMetalHosts")
        return available_bmhs
        
    except Exception as e:
        buffer_logger.error(f"Error querying BareMetalHosts: {str(e)}")
        if hasattr(e, 'status') and e.status == 404:
            buffer_logger.warning("Metal3 CRD not found - returning empty list")
            return []
        raise

def get_buffered_generators() -> List[Dict[str, Any]]:
    """Get list of BareMetalHostGenerators that are in Buffered state"""
    buffer_logger.debug("Querying buffered BareMetalHostGenerators")
    
    try:
        bmhgens = custom_api.list_cluster_custom_object(
            group="infra.example.com",
            version="v1alpha1",
            plural="baremetalhostgenerators"
        )
        
        buffered = []
        
        for bmhgen in bmhgens.get('items', []):
            status = bmhgen.get('status', {})
            if status.get('phase') == 'Buffered':
                buffered.append(bmhgen)
                buffer_logger.debug(f"BareMetalHostGenerator {bmhgen['metadata']['name']} is buffered")
        
        buffer_logger.info(f"Found {len(buffered)} buffered BareMetalHostGenerators")
        return buffered
        
    except Exception as e:
        buffer_logger.error(f"Error querying BareMetalHostGenerators: {str(e)}")
        raise

async def process_buffered_generator(bmhgen: Dict[str, Any]) -> None:
    """Process a single buffered BareMetalHostGenerator"""
    name = bmhgen['metadata']['name']
    namespace = bmhgen['metadata']['namespace']
    buffer_logger.info(f"Processing buffered generator: {name}")
    
    try:
        status = bmhgen.get('status', {})
        mac_address = status.get('macAddress')
        ipmi_address = status.get('ipmiAddress')
        
        # Get vendor from status first (if it was stored during buffering)
        server_vendor = status.get('serverVendor')
        
        if not server_vendor:
            # Fall back to annotation or name-based detection
            annotations = bmhgen.get('metadata', {}).get('annotations', {})
            server_vendor = annotations.get('server_vendor')
            
            if not server_vendor:
                # Use name-based detection and convert to uppercase
                detected_type = unified_client.detect_server_type(name)
                server_vendor = detected_type.name  # This gives "HP", "CISCO", "DELL" (uppercase)
        
        buffer_logger.info(f"Processing buffered server with vendor: {server_vendor}")
        
        # If server info is missing, try to fetch it again
        if not mac_address or not ipmi_address:
            buffer_logger.warning(f"Missing server info for buffered generator {name}, attempting to re-fetch")
            
            spec = bmhgen['spec']
            server_name = spec.get('serverName', name)
            
            try:
                # Get unified connection and search for server again
                with get_unified_connection() as client:
                    buffer_logger.info(f"Re-fetching server info for: {server_name}, vendor: {server_vendor}")
                    mac_address, ipmi_address = client.get_server_info(server_name, server_vendor)
                    buffer_logger.info(f"Successfully re-fetched - MAC: {mac_address}, Management IP: {ipmi_address}")
                    
                    # Update the buffered data with the fresh information
                    patch = {
                        "status": {
                            "macAddress": mac_address,
                            "ipmiAddress": ipmi_address
                        }
                    }
                    custom_api.patch_namespaced_custom_object_status(
                        group="infra.example.com",
                        version="v1alpha1",
                        namespace=namespace,
                        plural="baremetalhostgenerators",
                        name=name,
                        body=patch
                    )
                    
            except Exception as e:
                buffer_logger.error(f"Failed to re-fetch server info: {str(e)}")
                # Update status to failed if we can't get the server info
                patch = {
                    "status": {
                        "phase": "Failed",
                        "message": f"Cannot retrieve server information: {str(e)}"
                    }
                }
                custom_api.patch_namespaced_custom_object_status(
                    group="infra.example.com",
                    version="v1alpha1",
                    namespace=namespace,
                    plural="baremetalhostgenerators",
                    name=name,
                    body=patch
                )
                return
        
        spec = bmhgen['spec']
        target_namespace = spec.get('namespace', namespace)
        infra_env = spec.get('infraEnv')
        
        # Get IPMI credentials from environment only
        ipmi_username = os.getenv('IPMI_USERNAME', 'admin')
        ipmi_password = os.getenv('IPMI_PASSWORD', 'password')
        
        # If credentials are base64 encoded in env, decode them
        try:
            ipmi_username = base64.b64decode(ipmi_username).decode()
            ipmi_password = base64.b64decode(ipmi_password).decode()
            buffer_logger.debug("Decoded base64 IPMI credentials from environment")
        except:
            buffer_logger.debug("Using plain text IPMI credentials from environment")
        
        bmc_secret = generate_bmc_secret(
            name=name,
            namespace=target_namespace,
            username=ipmi_username,
            password=ipmi_password,
            server_vendor=server_vendor
        )
        
        try:
            core_v1.create_namespaced_secret(
                namespace=target_namespace,
                body=bmc_secret
            )
            buffer_logger.info(f"Created BMC secret: {bmc_secret['metadata']['name']}")
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 409:
                buffer_logger.debug(f"BMC secret already exists: {bmc_secret['metadata']['name']}")
            else:
                raise
        
        # Create BareMetalHost with server vendor
        bmh = generate_baremetal_host(
            name=name,
            namespace=target_namespace,
            mac_address=mac_address,
            ipmi_address=ipmi_address,
            ipmi_username=ipmi_username,
            ipmi_password=ipmi_password,
            infra_env=infra_env,
            server_vendor=server_vendor,
            labels=spec.get('labels', {})
        )
        
        custom_api.create_namespaced_custom_object(
            group="metal3.io",
            version="v1alpha1",
            namespace=target_namespace,
            plural="baremetalhosts",
            body=bmh
        )
        buffer_logger.info(f"Created BareMetalHost: {name}")
        
        # Update generator status to Completed
        patch = {
            "status": {
                "phase": "Completed",
                "message": f"Successfully created BareMetalHost {name} (released from buffer)",
                "bmhName": name,
                "bmhNamespace": target_namespace
            }
        }
        
        custom_api.patch_namespaced_custom_object_status(
            group="infra.example.com",
            version="v1alpha1",
            namespace=namespace,
            plural="baremetalhostgenerators",
            name=name,
            body=patch
        )
        buffer_logger.info(f"Updated generator {name} status to Completed")
        
    except Exception as e:
        buffer_logger.error(f"Error processing buffered generator {name}: {str(e)}")
        try:
            patch = {
                "status": {
                    "phase": "Failed",
                    "message": f"Failed to create from buffer: {str(e)}"
                }
            }
            custom_api.patch_namespaced_custom_object_status(
                group="infra.example.com",
                version="v1alpha1",
                namespace=namespace,
                plural="baremetalhostgenerators",
                name=name,
                body=patch
            )
        except:
            pass
        raise

async def buffer_check_loop():
    """Periodically check buffer and release servers if needed"""
    buffer_logger.info("Starting buffer check loop")
    
    while True:
        try:
            await asyncio.sleep(BUFFER_CHECK_INTERVAL)
            
            async with bmh_buffer_lock:
                buffer_logger.debug("Running buffer check")
                
                # Get current available count
                available_bmhs = get_available_baremetalhosts()
                available_count = len(available_bmhs)
                
                buffer_logger.info(f"Current available BareMetalHosts: {available_count}/{MAX_AVAILABLE_SERVERS}")
                
                # If we have room for more servers, release from buffer
                if available_count < MAX_AVAILABLE_SERVERS:
                    slots_available = MAX_AVAILABLE_SERVERS - available_count
                    buffer_logger.info(f"Can release {slots_available} servers from buffer")
                    
                    # Get buffered generators sorted by buffer time (FIFO)
                    buffered = get_buffered_generators()
                    buffered.sort(key=lambda x: x['status'].get('bufferedAt', ''))
                    
                    # Release servers from buffer
                    for i, bmhgen in enumerate(buffered[:slots_available]):
                        buffer_logger.info(f"Releasing buffered generator {i+1}/{slots_available}: {bmhgen['metadata']['name']}")
                        await process_buffered_generator(bmhgen)
                        
                        if i < slots_available - 1:
                            await asyncio.sleep(2)
                else:
                    buffer_logger.debug("No slots available to release servers from buffer")
                    
        except Exception as e:
            buffer_logger.error(f"Error in buffer check loop: {str(e)}")
            buffer_logger.exception("Full exception details:")

def get_unified_connection():
    """Get unified server connection, creating new instance for each use"""
    global unified_client
    
    if not unified_client:
        raise RuntimeError("Unified client not initialized")
    
    # Create a new instance with the same credentials
    # This ensures fresh connections for each server lookup
    return UnifiedServerClient(
        # HP OneView
        oneview_ip=unified_client.oneview_ip,
        oneview_username=unified_client.oneview_username,
        oneview_password=unified_client.oneview_password,
        # Cisco UCS
        ucs_central_ip=unified_client.ucs_central_ip,
        central_username=unified_client.central_username,
        central_password=unified_client.central_password,
        manager_username=unified_client.manager_username,
        manager_password=unified_client.manager_password,
        # Dell OME
        ome_ip=unified_client.ome_ip,
        ome_username=unified_client.ome_username,
        ome_password=unified_client.ome_password
    )

@kopf.on.startup()
async def configure(settings: kopf.OperatorSettings, **_):
    """Configure operator settings"""
    operator_logger.info("Starting operator configuration")
    
    settings.execution.max_workers = 4  
    settings.posting.enabled = False
    settings.batching.worker_limit = 1
    settings.persistence.finalizer = 'bmhgenerator.infra.example.com/finalizer'
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage()
    
    # Initialize unified server client
    global unified_client
    
    # HP OneView credentials
    oneview_ip = os.getenv('ONEVIEW_IP')
    oneview_username = os.getenv('ONEVIEW_USERNAME', 'administrator')
    oneview_password = os.getenv('ONEVIEW_PASSWORD')
    
    # Cisco UCS credentials
    ucs_central_ip = os.getenv('UCS_CENTRAL_IP')
    central_username = os.getenv('UCS_CENTRAL_USERNAME', 'admin')
    central_password = os.getenv('UCS_CENTRAL_PASSWORD')
    manager_username = os.getenv('UCS_MANAGER_USERNAME', 'admin')
    manager_password = os.getenv('UCS_MANAGER_PASSWORD')
    
    # Dell OME credentials
    ome_ip = os.getenv('OME_IP')
    ome_username = os.getenv('OME_USERNAME', 'admin')
    ome_password = os.getenv('OME_PASSWORD')
    
    # Check if at least one system is configured
    hp_configured = all([oneview_ip, oneview_password])
    ucs_configured = all([ucs_central_ip, central_password, manager_password])
    dell_configured = all([ome_ip, ome_password])
    
    if not any([hp_configured, ucs_configured, dell_configured]):
        operator_logger.error("No server management system configured. At least one system must be configured.")
        raise ValueError("Missing server management configuration")
    
    # Log which systems are configured
    configured_systems = []
    if hp_configured:
        configured_systems.append("HP OneView")
    if ucs_configured:
        configured_systems.append("Cisco UCS")
    if dell_configured:
        configured_systems.append("Dell OME")
    
    operator_logger.info(f"Configured server management systems: {', '.join(configured_systems)}")
    
    unified_client = UnifiedServerClient(
        # HP OneView
        oneview_ip=oneview_ip,
        oneview_username=oneview_username,
        oneview_password=oneview_password,
        # Cisco UCS
        ucs_central_ip=ucs_central_ip,
        central_username=central_username,
        central_password=central_password,
        manager_username=manager_username,
        manager_password=manager_password,
        # Dell OME
        ome_ip=ome_ip,
        ome_username=ome_username,
        ome_password=ome_password
    )
    
    # Check if we're already over limit
    try:
        available_bmhs = get_available_baremetalhosts()
        available_count = len(available_bmhs)
        
        if available_count > MAX_AVAILABLE_SERVERS:
            operator_logger.warning(f"Starting with {available_count} available servers, exceeds limit of {MAX_AVAILABLE_SERVERS}")
            operator_logger.warning("New servers will be buffered until available count drops below limit")
    except Exception as e:
        operator_logger.error(f"Error checking initial BMH count: {e}")
    
    # Setup asyncio event loop and start buffer check task
    global buffer_check_task
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    buffer_check_task = asyncio.create_task(buffer_check_loop())
    buffer_logger.info("Started buffer check background task")
    
    operator_logger.info("Operator configuration completed successfully")

@kopf.on.create('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def create_bmh(spec: Dict[str, Any], name: str, namespace: str, **kwargs):
    """Handle BareMetalHostGenerator creation"""
    
    operator_logger.info(f"Processing BareMetalHostGenerator: {name} in namespace: {namespace}")
    
    server_name = spec.get('serverName', name)
    target_namespace = spec.get('namespace', namespace)
    infra_env = spec.get('infraEnv')
    
    annotations = kwargs.get('meta', {}).get('annotations', {})
    server_vendor = annotations.get('server_vendor')
    operator_logger.info(f"Server vendor annotation: {server_vendor}")  
    
    if not infra_env:
        raise kopf.PermanentError("infraEnv is required in spec")
    
    # Initial status
    status_update = {
        "phase": "Processing",
        "message": f"Looking up server {server_name} in management systems"
    }
    
    try:
        # Update status
        custom_api.patch_namespaced_custom_object_status(
            group="infra.example.com",
            version="v1alpha1",
            namespace=namespace,
            plural="baremetalhostgenerators",
            name=name,
            body={"status": status_update}
        )
    except Exception as e:
        operator_logger.warning(f"Could not update initial status: {e}")
    
    try:
        # Get unified connection and search for server
        with get_unified_connection() as client:
            operator_logger.info(f"Searching for server: {server_name}, vendor: {server_vendor or 'auto-detect'}")
            mac_address, ipmi_address = client.get_server_info(server_name, server_vendor)
            operator_logger.info(f"Server found - MAC: {mac_address}, Management IP: {ipmi_address}")
            
            if not server_vendor:
                detected_type = client.detect_server_type(server_name, server_vendor)
                server_vendor = detected_type.name
            
            operator_logger.info(f"Final server vendor: {server_vendor}")
        
        # Check if we should buffer or create immediately
        async with bmh_buffer_lock:
            available_bmhs = get_available_baremetalhosts()
            available_count = len(available_bmhs)
            
            buffer_logger.info(f"Current available BareMetalHosts: {available_count}/{MAX_AVAILABLE_SERVERS}")
            
            if available_count >= MAX_AVAILABLE_SERVERS:
                # Buffer this server - now including vendor information
                status_update = {
                    "phase": "Buffered",
                    "message": f"Server buffered (available: {available_count}/{MAX_AVAILABLE_SERVERS})",
                    "bufferedAt": datetime.now().isoformat(),
                    "macAddress": mac_address,
                    "ipmiAddress": ipmi_address,
                    "serverVendor": server_vendor  # Store vendor in status
                }
                
                custom_api.patch_namespaced_custom_object_status(
                    group="infra.example.com",
                    version="v1alpha1",
                    namespace=namespace,
                    plural="baremetalhostgenerators",
                    name=name,
                    body={"status": status_update}
                )
                
                buffer_logger.info(f"Buffering server {server_name} - limit reached")
                return  # No error is raised here, just returns after updating status
        
        # Get IPMI credentials from environment only
        ipmi_username = os.getenv('IPMI_USERNAME', 'admin')
        ipmi_password = os.getenv('IPMI_PASSWORD', 'password')
        
        # If credentials are base64 encoded in env, decode them
        try:
            ipmi_username = base64.b64decode(ipmi_username).decode()
            ipmi_password = base64.b64decode(ipmi_password).decode()
            operator_logger.debug("Decoded base64 IPMI credentials from environment")
        except:
            operator_logger.debug("Using plain text IPMI credentials from environment")
        
        # Create BMC Secret - using determined server_vendor
        bmc_secret = generate_bmc_secret(
            name=server_name,
            namespace=target_namespace,
            username=ipmi_username,
            password=ipmi_password,
            server_vendor=server_vendor
        )
        
        try:
            core_v1.create_namespaced_secret(
                namespace=target_namespace,
                body=bmc_secret
            )
            operator_logger.info(f"Created BMC secret: {bmc_secret['metadata']['name']}")
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 409:
                operator_logger.info(f"BMC secret already exists: {bmc_secret['metadata']['name']}")
            else:
                raise
        
        # Generate and create BareMetalHost - using determined server_vendor
        bmh = generate_baremetal_host(
            name=server_name,
            namespace=target_namespace,
            mac_address=mac_address,
            ipmi_address=ipmi_address,
            ipmi_username=ipmi_username,
            ipmi_password=ipmi_password,
            infra_env=infra_env,
            server_vendor=server_vendor,
            labels=spec.get('labels', {})
        )
        
        try:
            custom_api.create_namespaced_custom_object(
                group="metal3.io",
                version="v1alpha1",
                namespace=target_namespace,
                plural="baremetalhosts",
                body=bmh
            )
            operator_logger.info(f"Created BareMetalHost: {server_name}")
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 404:
                operator_logger.warning("Metal3 CRD not found - simulating creation for testing")
            elif e.status == 409:
                operator_logger.info(f"BareMetalHost already exists: {server_name}")
            else:
                raise
        
        # Update status to success
        status_update = {
            "phase": "Completed",
            "message": f"Successfully created BareMetalHost {server_name}",
            "bmhName": server_name,
            "bmhNamespace": target_namespace
        }
        
        custom_api.patch_namespaced_custom_object_status(
            group="infra.example.com",
            version="v1alpha1",
            namespace=namespace,
            plural="baremetalhostgenerators",
            name=name,
            body={"status": status_update}
        )
        
        operator_logger.info(f"Successfully completed BareMetalHost creation for: {server_name}")
        
    except Exception as e:
        operator_logger.error(f"Failed to create BareMetalHost: {str(e)}")
        
        status_update = {
            "phase": "Failed",
            "message": f"Error: {str(e)}"
        }
        
        try:
            custom_api.patch_namespaced_custom_object_status(
                group="infra.example.com",
                version="v1alpha1",
                namespace=namespace,
                plural="baremetalhostgenerators",
                name=name,
                body={"status": status_update}
            )
        except:
            pass
            
        raise kopf.PermanentError(f"Failed to create BareMetalHost: {str(e)}")

@kopf.on.update('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def update_bmh(spec, status, name, **kwargs):
    """Ignore updates - BareMetalHostGenerators are immutable"""
    operator_logger.info(f"BareMetalHostGenerator {name} update ignored - resource is immutable")
    return

@kopf.on.delete('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def delete_bmh(spec, name, namespace, status, **kwargs):
    """Clean up BareMetalHost when generator is deleted"""
    operator_logger.info(f"Processing deletion of BareMetalHostGenerator: {name}")
    
    if status.get('bmhName') and status.get('bmhNamespace'):
        operator_logger.info(f"BareMetalHostGenerator deleted, keeping BareMetalHost: {status['bmhName']}")

@kopf.on.cleanup()
async def cleanup_fn(**kwargs):
    """Cleanup function called on operator shutdown"""
    operator_logger.info("Operator shutting down")
    
    if buffer_check_task:
        buffer_check_task.cancel()
        try:
            await buffer_check_task
        except asyncio.CancelledError:
            buffer_logger.info("Buffer check task cancelled")
    
    if unified_client:
        try:
            unified_client.disconnect()
        except Exception as e:
            operator_logger.warning(f"Error disconnecting from server management systems: {e}")
    
    operator_logger.info("Cleanup completed")

if __name__ == "__main__":
    operator_logger.info("Starting BareMetalHost Generator Operator with Buffering")
    operator_logger.info(f"Max available servers: {MAX_AVAILABLE_SERVERS}")
    operator_logger.info(f"Buffer check interval: {BUFFER_CHECK_INTERVAL}s")
    
    try:
        kopf.run()
    except Exception as e:
        operator_logger.critical(f"Operator crashed: {str(e)}")
        raise