import requests
import logging
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings

# Disable SSL warnings for self-signed certificates
disable_warnings(InsecureRequestWarning)

# Configure logging
hp_logger = logging.getLogger('hp_oneview_client')
hp_logger.setLevel(logging.INFO)


class HPOneViewClient:
    def __init__(self, oneview_ip=None, oneview_username=None, oneview_password=None):
        """Initialize HP OneView client"""
        self.oneview_ip = oneview_ip
        self.oneview_username = oneview_username
        self.oneview_password = oneview_password
        self.session = None
        self.auth_token = None
        self.base_url = f"https://{oneview_ip}" if oneview_ip else None
        hp_logger.info(f"Initialized HP OneView client for: {oneview_ip}")
    
    def _ensure_connected(self):
        """Ensure we have an active session with OneView"""
        if not self.session or not self.auth_token:
            hp_logger.info(f"Connecting to HP OneView at {self.oneview_ip}")
            
            if not all([self.oneview_ip, self.oneview_username, self.oneview_password]):
                raise ValueError("OneView IP, username, and password must be provided")
            
            self.session = requests.Session()
            self.session.verify = False
            
            # Authenticate with OneView
            auth_url = f"{self.base_url}/rest/login-sessions"
            auth_data = {
                "userName": self.oneview_username,
                "password": self.oneview_password
            }
            
            # OneView requires specific headers
            headers = {
                "Content-Type": "application/json",
                "X-API-Version": "2000"  # Latest API version
            }
            
            response = self.session.post(auth_url, json=auth_data, headers=headers)
            response.raise_for_status()
            
            # Extract session ID/auth token
            self.auth_token = response.json().get('sessionID')
            
            # Update session headers with auth token
            self.session.headers.update({
                'Auth': self.auth_token,
                'X-API-Version': '2000'
            })
            
            hp_logger.info("Successfully connected to HP OneView")
    
    def get_server_info(self, server_name):
        """Get server MAC and iLO IP by server name or serial number"""
        hp_logger.info(f"Getting server info for: {server_name}")
        
        self._ensure_connected()
        
        # Search for server hardware by name or serial number
        # OneView uses query parameters for filtering
        servers_url = f"{self.base_url}/rest/server-hardware"
        params = {
            'filter': f'name="{server_name}" OR serialNumber="{server_name}"'
        }
        
        response = self.session.get(servers_url, params=params)
        response.raise_for_status()
        
        servers = response.json().get('members', [])
        
        if not servers:
            hp_logger.error(f"Server {server_name} not found")
            raise ValueError(f"Server {server_name} not found in HP OneView")
        
        server = servers[0]  # Take first match
        
        # Get iLO IP from mpHostInfo
        ilo_ip = ""
        mp_host_info = server.get('mpHostInfo', {})
        mp_addresses = mp_host_info.get('mpIpAddresses', [])
        
        for addr_info in mp_addresses:
            if addr_info.get('type') == 'DHCP' or addr_info.get('type') == 'Static':
                ilo_ip = addr_info.get('address', '')
                if ilo_ip:
                    break
        
        # Alternative: check remoteConsoleUrl if available
        if not ilo_ip and server.get('remoteConsoleUrl'):
            # Extract IP from URL like https://192.168.1.100:443
            import re
            match = re.search(r'https?://([^:]+)', server.get('remoteConsoleUrl', ''))
            if match:
                ilo_ip = match.group(1)
        
        # Get MAC address from port information
        mac_address = self._get_primary_mac(server.get('uri'))
        
        hp_logger.info(f"Retrieved info for {server_name} - MAC: {mac_address}, iLO IP: {ilo_ip}")
        return mac_address, ilo_ip
    
    def _get_primary_mac(self, server_uri):
        """Get primary MAC address for server"""
        try:
            # Get server hardware details including port info
            response = self.session.get(f"{self.base_url}{server_uri}")
            response.raise_for_status()
            
            server_data = response.json()
            
            # Look for MAC in portMap (physical ports)
            port_map = server_data.get('portMap', {})
            device_slots = port_map.get('deviceSlots', [])
            
            # Find first Ethernet port with valid MAC
            for slot in device_slots:
                for port in slot.get('physicalPorts', []):
                    mac = port.get('mac', '')
                    if mac and mac != '00:00:00:00:00:00':
                        return mac
            
            # Alternative: Check server profile if assigned
            server_profile_uri = server_data.get('serverProfileUri')
            if server_profile_uri:
                return self._get_mac_from_profile(server_profile_uri)
            
            return "No MAC address found"
            
        except Exception as e:
            hp_logger.error(f"Error getting MAC address: {str(e)}")
            return "No MAC address found"
    
    def _get_mac_from_profile(self, profile_uri):
        """Get MAC from server profile connections"""
        try:
            response = self.session.get(f"{self.base_url}{profile_uri}")
            response.raise_for_status()
            
            profile = response.json()
            connections = profile.get('connectionSettings', {}).get('connections', [])
            
            # Sort by connection ID and get first Ethernet MAC
            for conn in sorted(connections, key=lambda x: x.get('id', 0)):
                if conn.get('functionType') == 'Ethernet':
                    mac = conn.get('mac', '')
                    if mac and mac != '00:00:00:00:00:00':
                        return mac
            
            return "No MAC address found"
            
        except Exception as e:
            hp_logger.error(f"Error getting MAC from profile: {str(e)}")
            return "No MAC address found"
    
    def disconnect(self):
        """Disconnect from HP OneView"""
        if self.session and self.auth_token:
            try:
                # Logout from OneView
                logout_url = f"{self.base_url}/rest/login-sessions"
                self.session.delete(logout_url)
            except:
                pass
            finally:
                self.session.close()
                self.session = None
                self.auth_token = None
                hp_logger.info("Disconnected from HP OneView")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    client = HPOneViewClient(
        oneview_ip="192.168.1.100",
        oneview_username="administrator",
        oneview_password="password"
    )
    
    try:
        mac, ilo_ip = client.get_server_info("MYSERVER01")
        print(f"MAC: {mac}, iLO: {ilo_ip}")
    finally:
        client.disconnect()