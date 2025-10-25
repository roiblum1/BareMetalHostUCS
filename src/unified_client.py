import logging
from enum import Enum
from typing import Optional, Tuple

import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)


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
    
    def detect_server_type(self, server_name: str) -> ServerType:
        """
        Detect server type based on naming convention.
        
        Args:
            server_name: Name of the server
            
        Returns:
            ServerType enum value
        """
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
    
    def get_server_info(self, server_name: str) -> Tuple[str, str]:
        """
        Get server MAC address and management IP based on server name.
        Automatically detects server type and searches efficiently.
        
        Args:
            server_name: Name of the server
            
        Returns:
            Tuple of (mac_address, management_ip)
        """
        logger.info(f"Getting server info for: {server_name}")
        
        # Detect server type based on naming convention
        server_type = self.detect_server_type(server_name)
        
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