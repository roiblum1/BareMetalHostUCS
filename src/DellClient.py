import requests
import json
import logging
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings

# Disable SSL warnings for self-signed certificates
disable_warnings(InsecureRequestWarning)

# Configure logging
dell_logger = logging.getLogger('dell_ome_client')
dell_logger.setLevel(logging.INFO)

class DellOMEClient:
    def __init__(self, ome_ip=None, ome_username=None, ome_password=None):
        """
        Initialize Dell OpenManage Enterprise client
        
        Args:
            ome_ip: IP address of the OpenManage Enterprise console
            ome_username: Username for OME authentication
            ome_password: Password for OME authentication
        """
        self.ome_ip = ome_ip
        self.ome_username = ome_username
        self.ome_password = ome_password
        self.session = None
        self.auth_token = None
        self.base_url = f"https://{ome_ip}/api" if ome_ip else None
        dell_logger.info(f"Initialized Dell OME client for: {ome_ip}")
        
    def connect(self):
        """Connect to Dell OpenManage Enterprise"""
        dell_logger.info(f"Attempting to connect to Dell OME at {self.ome_ip}")
        
        if not all([self.ome_ip, self.ome_username, self.ome_password]):
            dell_logger.error("Missing required OME connection parameters")
            raise ValueError("OME IP, username, and password must be provided")
        
        try:
            self.session = requests.Session()
            self.session.verify = False  # For self-signed certificates
            
            # Authenticate with OME
            auth_url = f"{self.base_url}/SessionService/Sessions"
            auth_data = {
                "UserName": self.ome_username,
                "Password": self.ome_password,
                "SessionType": "API"
            }
            
            response = self.session.post(auth_url, json=auth_data)
            response.raise_for_status()
            
            # Extract authentication token
            auth_info = response.json()
            self.auth_token = response.headers.get('X-Auth-Token')
            self.session.headers.update({'X-Auth-Token': self.auth_token})
            
            dell_logger.info(f"Successfully connected to Dell OME at {self.ome_ip}")
            
        except requests.exceptions.RequestException as e:
            dell_logger.error(f"Failed to connect to Dell OME: {str(e)}")
            raise
        except Exception as e:
            dell_logger.error(f"Unexpected error connecting to Dell OME: {str(e)}")
            raise
    
    def get_all_servers(self):
        """Query all servers from Dell OpenManage Enterprise"""
        dell_logger.debug("Querying all servers from OME")
        
        if not self.session or not self.auth_token:
            dell_logger.error("Not connected to Dell OME")
            raise RuntimeError("Not connected to Dell OME. Call connect() first.")
        
        try:
            # Get all devices of type Server
            devices_url = f"{self.base_url}/DeviceService/Devices"
            params = {
                '$filter': 'Type eq 1000',  # 1000 = Server type in OME
                '$top': 5000  # Adjust based on your environment
            }
            
            response = self.session.get(devices_url, params=params)
            response.raise_for_status()
            
            devices_data = response.json()
            servers = devices_data.get('value', [])
            
            dell_logger.info(f"Found {len(servers)} servers in Dell OME")
            return servers
            
        except requests.exceptions.RequestException as e:
            dell_logger.error(f"Failed to query servers: {str(e)}")
            raise
        except Exception as e:
            dell_logger.error(f"Unexpected error querying servers: {str(e)}")
            raise
    
    def get_server_info(self, server_name):
        """Get server MAC and iDRAC IP address by server name"""
        dell_logger.info(f"Getting server info for: {server_name}")
        
        if not self.session:
            dell_logger.debug("Not connected, attempting to connect")
            self.connect()
            
        servers = self.get_all_servers()
        mac_address, idrac_ip = self.get_dell_info_for_node(server_name, servers)
        
        if not mac_address or not idrac_ip:
            dell_logger.error(f"Could not find complete info for server {server_name}")
            raise ValueError(f"Could not find server {server_name} or retrieve its information")
        
        dell_logger.info(f"Retrieved info for {server_name} - MAC: {mac_address}, iDRAC IP: {idrac_ip}")
        return mac_address, idrac_ip
    
    def get_dell_info_for_node(self, node_name, servers):
        """Extract Dell server information for a specific node"""
        dell_logger.info(f"Processing node: {node_name}")
        
        for server in servers:
            server_display_name = server.get('DeviceName', '')
            server_service_tag = server.get('DeviceServiceTag', '')
            
            dell_logger.debug(f"Checking server: {server_display_name} (Service Tag: {server_service_tag})")
            
            # Check both device name and service tag for match
            if (node_name.upper() == server_display_name.upper() or 
                node_name.upper() == server_service_tag.upper()):
                
                dell_logger.info(f"Found matching server: {server_display_name}")
                
                try:
                    server_id = server.get('Id')
                    
                    # Get iDRAC IP
                    idrac_ip = self._get_idrac_ip(server)
                    
                    # Get MAC address
                    mac_address = self._get_mac_address(server_id)
                    
                    dell_logger.info(f"Successfully retrieved info - MAC: {mac_address}, iDRAC IP: {idrac_ip}")
                    return mac_address, idrac_ip
                    
                except Exception as e:
                    dell_logger.error(f"Error retrieving data for {node_name}: {str(e)}")
                    dell_logger.exception("Full exception details:")
        
        dell_logger.warning(f"No matching server found for node: {node_name}")
        return None, None
    
    def _get_idrac_ip(self, server):
        """Extract iDRAC IP address from server data"""
        dell_logger.debug("Extracting iDRAC IP")
        
        try:
            # The iDRAC IP is typically in the DeviceManagement field
            device_mgmt = server.get('DeviceManagement', [])
            
            idrac_ip = ""
            for mgmt in device_mgmt:
                if mgmt.get('ManagementType') == 2:  # 2 = iDRAC
                    network_address = mgmt.get('NetworkAddress', '')
                    if network_address:
                        idrac_ip = network_address
                        dell_logger.info(f"Found iDRAC IP: {idrac_ip}")
                        break
            
            # Alternative: Check the management IP directly
            if not idrac_ip and server.get('ManagementIP'):
                idrac_ip = server.get('ManagementIP')
                dell_logger.info(f"Found iDRAC IP from ManagementIP: {idrac_ip}")
            
            if not idrac_ip:
                dell_logger.warning("No iDRAC IP found")
                
            return idrac_ip
            
        except Exception as e:
            dell_logger.error(f"Error retrieving iDRAC IP: {str(e)}")
            return ""
    
    def _get_mac_address(self, server_id):
        """Extract MAC address from server network interfaces"""
        dell_logger.debug(f"Querying network interfaces for server ID: {server_id}")
        
        try:
            # Get network interfaces for the server
            interfaces_url = f"{self.base_url}/DeviceService/Devices({server_id})/InventoryDetails('networkInterfaces')"
            
            response = self.session.get(interfaces_url)
            response.raise_for_status()
            
            interfaces_data = response.json()
            interfaces = interfaces_data.get('InventoryInfo', [])
            
            dell_logger.debug(f"Found {len(interfaces)} network interfaces")
            
            mac_address = ""
            if interfaces:
                # Sort interfaces by name/port number to get consistent ordering
                sorted_interfaces = sorted(interfaces, key=lambda x: x.get('Name', ''))
                
                # Look for the first Ethernet interface with a MAC address
                for interface in sorted_interfaces:
                    mac = interface.get('MacAddress', '')
                    if mac and mac != '00:00:00:00:00:00':
                        mac_address = mac
                        dell_logger.info(f"Found MAC address: {mac_address}")
                        break
                
                if not mac_address:
                    dell_logger.warning("No valid MAC address found in network interfaces")
            else:
                dell_logger.warning("No network interfaces found")
                
            return mac_address if mac_address else "No MAC address found"
            
        except requests.exceptions.RequestException as e:
            dell_logger.error(f"Error retrieving MAC address: {str(e)}")
            return "No MAC address found"
        except Exception as e:
            dell_logger.error(f"Unexpected error retrieving MAC address: {str(e)}")
            return "No MAC address found"
    
    def get_server_details(self, server_id):
        """Get detailed information about a specific server"""
        dell_logger.debug(f"Getting detailed info for server ID: {server_id}")
        
        try:
            details_url = f"{self.base_url}/DeviceService/Devices({server_id})"
            response = self.session.get(details_url)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            dell_logger.error(f"Error retrieving server details: {str(e)}")
            raise
    
    def disconnect(self):
        """Disconnect from Dell OpenManage Enterprise"""
        if self.session and self.auth_token:
            try:
                # Logout from OME
                logout_url = f"{self.base_url}/SessionService/Sessions"
                self.session.delete(logout_url)
                
                self.session.close()
                self.session = None
                self.auth_token = None
                
                dell_logger.info("Disconnected from Dell OME")
                
            except Exception as e:
                dell_logger.warning(f"Error during Dell OME logout: {str(e)}")
                # Still clean up the session
                if self.session:
                    self.session.close()
                self.session = None
                self.auth_token = None


# Example usage
if __name__ == "__main__":
    # Configure logging to see output
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Example configuration
    ome_client = DellOMEClient(
        ome_ip="192.168.1.100",
        ome_username="admin",
        ome_password="password123"
    )
    
    try:
        # Connect to OME
        ome_client.connect()
        
        # Get info for a specific server
        mac, idrac_ip = ome_client.get_server_info("MYSERVER01")
        print(f"MAC Address: {mac}")
        print(f"iDRAC IP: {idrac_ip}")
        
        # Get all servers
        all_servers = ome_client.get_all_servers()
        print(f"Total servers: {len(all_servers)}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Always disconnect when done
        ome_client.disconnect()