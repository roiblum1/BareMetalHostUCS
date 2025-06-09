import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)
ucs_logger = logging.getLogger('ucs_client')
class UCSClient:
    def __init__(self, ucs_central_ip=None, central_username=None, central_password=None, 
                 manager_username=None, manager_password=None):
        self.ucs_central_ip = ucs_central_ip
        self.central_username = central_username
        self.central_password = central_password
        self.manager_username = manager_username
        self.manager_password = manager_password
        self.ucsc_handle = None
        ucs_logger.info(f"Initialized UCS client for UCS Central: {ucs_central_ip}")
        
    def connect(self):
        """Connect to UCS Central"""
        ucs_logger.info(f"Attempting to connect to UCS Central at {self.ucs_central_ip}")
        
        if not all([self.ucs_central_ip, self.central_username, self.central_password, 
                   self.manager_username, self.manager_password]):
            ucs_logger.error("Missing required UCS connection parameters")
            raise ValueError("UCS Central IP, central credentials, and manager credentials must be provided")
        
        try:
            self.ucsc_handle = UcscHandle(self.ucs_central_ip, self.central_username, self.central_password)
            self.ucsc_handle.login()
            ucs_logger.info(f"Successfully connected to UCS Central at {self.ucs_central_ip}")
        except Exception as e:
            ucs_logger.error(f"Failed to connect to UCS Central: {str(e)}")
            raise
        
    def get_all_servers(self):
        """Query all logical servers from UCS Central"""
        ucs_logger.debug("Querying all logical servers")
        
        if not self.ucsc_handle:
            ucs_logger.error("Not connected to UCS Central")
            raise RuntimeError("Not connected to UCS Central. Call connect() first.")
        
        try:
            servers = self.ucsc_handle.query_classid("lsServer")
            ucs_logger.info(f"Found {len(servers)} servers in UCS Central")
            return servers
        except Exception as e:
            ucs_logger.error(f"Failed to query servers: {str(e)}")
            raise
    
    def get_server_info(self, server_name):
        """Get server MAC and IPMI address by server name"""
        ucs_logger.info(f"Getting server info for: {server_name}")
        
        if not self.ucsc_handle:
            ucs_logger.debug("Not connected, attempting to connect")
            self.connect()
            
        servers = self.get_all_servers()
        mac_address, kvm_ip = self.get_ucs_info_for_node(server_name, servers)
        
        if not mac_address or not kvm_ip:
            ucs_logger.error(f"Could not find complete info for server {server_name}")
            raise ValueError(f"Could not find server {server_name} or retrieve its information")
        
        ucs_logger.info(f"Retrieved info for {server_name} - MAC: {mac_address}, KVM IP: {kvm_ip}")
        return mac_address, kvm_ip
    
    def get_ucs_info_for_node(self, node_name, servers):
        """Extract UCS information for a specific node"""
        ucs_logger.info(f"Processing node: {node_name}")
        
        for server in servers:
            ucs_logger.debug(f"Checking server: {server.name} (DN: {server.dn})")
            
            if node_name.upper() == server.name.upper():
                ucs_logger.info(f"Found matching server: {server.name}")
                domain = server.domain
                rack_id = server.pn_dn.split("-")[-1] if hasattr(server, 'pn_dn') else ""
                ucsm_handle = None
                
                try:
                    ucs_logger.debug(f"Connecting to UCS Manager domain: {domain}")
                    ucsm_handle = UcsHandle(domain, self.manager_username, self.manager_password)
                    ucsm_handle.login()
                    
                    # Get server details from UCS Central (not UCS Manager)
                    server_details = self.ucsc_handle.query_dn(server.dn)
                    if not server_details:
                        ucs_logger.warning(f"No server details found for {node_name}")
                        continue
                    
                    ucs_logger.debug(f"Retrieved server details for DN: {server.dn}")
                    
                    kvm_ip = self._get_kvm_ip(ucsm_handle, server_details)
                    mac_address = self._get_mac_address(ucsm_handle, server_details)
                    
                    ucs_logger.info(f"Successfully retrieved info - MAC: {mac_address}, KVM IP: {kvm_ip}")
                    return mac_address, kvm_ip
                    
                except Exception as e:
                    ucs_logger.error(f"Error retrieving data for {node_name}: {str(e)}")
                    ucs_logger.exception("Full exception details:")
                    
                finally:
                    if ucsm_handle:
                        try:
                            ucsm_handle.logout()
                            ucs_logger.debug(f"Logged out from domain: {domain}")
                        except Exception as e:
                            ucs_logger.warning(f"Failed to logout from domain {domain}: {str(e)}")
        
        ucs_logger.warning(f"No matching server found for node: {node_name}")
        return None, None
    
    def _get_kvm_ip(self, ucsm_handle, server_details):
        """Extract KVM IP address from VnicIpV4PooledAddr"""
        ucs_logger.debug("Querying VnicIpV4PooledAddr for KVM IP")
        
        try:
            mgmt_interfaces = ucsm_handle.query_children(in_mo=server_details, class_id="VnicIpV4PooledAddr")
            ucs_logger.debug(f"Found {len(mgmt_interfaces)} IP pool addresses")
            
            kvm_ip = ""
            for iface in mgmt_interfaces:
                if hasattr(iface, 'addr') and iface.addr:
                    kvm_ip = str(iface.addr)
                    ucs_logger.info(f"Found KVM IP: {kvm_ip}")
                    break
            
            if not kvm_ip:
                ucs_logger.warning("No KVM IP found in VnicIpV4PooledAddr")
                
            return kvm_ip
            
        except Exception as e:
            ucs_logger.error(f"Error retrieving KVM IP: {str(e)}")
            return ""
    
    def _get_mac_address(self, ucsm_handle, server_details):
        """Extract MAC address from VnicEther (sorted by name)"""
        ucs_logger.debug("Querying VnicEther for MAC address")
        
        try:
            adapters = ucsm_handle.query_children(in_mo=server_details, class_id="VnicEther")
            ucs_logger.debug(f"Found {len(adapters)} VnicEther adapters")
            
            mac_address = ""
            if adapters:
                # Sort adapters by name (same as in your working script)
                sorted_adapters = sorted(adapters, key=lambda x: x.name[3:])
                
                if sorted_adapters and hasattr(sorted_adapters[0], 'addr'):
                    mac_address = sorted_adapters[0].addr
                    ucs_logger.info(f"Found MAC address: {mac_address}")
                else:
                    ucs_logger.warning("No MAC address found in first VnicEther adapter")
            else:
                ucs_logger.warning("No VnicEther adapters found")
                
            return mac_address if mac_address else "No MAC address found"
            
        except Exception as e:
            ucs_logger.error(f"Error retrieving MAC address: {str(e)}")
            return "No MAC address found"
    
    def disconnect(self):
        """Disconnect from UCS Central"""
        if self.ucsc_handle:
            try:
                self.ucsc_handle.logout()
                ucs_logger.info("Disconnected from UCS Central")
            except Exception as e:
                ucs_logger.warning(f"Error during UCS Central logout: {str(e)}")