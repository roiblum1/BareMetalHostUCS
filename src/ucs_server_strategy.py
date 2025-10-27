import logging
import os
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Tuple, Dict, Type
import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from server_strategy import ServerStrategy

disable_warnings(InsecureRequestWarning)
logger = logging.getLogger('cisco_strategy')

class CiscoServerStrategy(ServerStrategy):
    
    def __init__(self, credentials: Dict[str, str]):
        self.credentials = credentials
        self._ucsc_handle = None
        self._UcsHandle = None
        self._cache = None
    
    def is_configured(self) -> bool:
        """Check if Cisco UCS Central and BMC credentials are configured."""
        # Check management system credentials
        management_configured = all([
            self.credentials.get("central_ip"),
            self.credentials.get("central_username"),
            self.credentials.get("central_password"),
            self.credentials.get("manager_username"),
            self.credentials.get("manager_password")
        ])

        # Check BMC credentials
        bmc_configured = all([
            os.getenv('CISCO_BMC_USERNAME'),
            os.getenv('CISCO_BMC_PASSWORD')
        ])

        if management_configured and not bmc_configured:
            logger.warning("Cisco UCS is configured but CISCO_BMC_USERNAME/CISCO_BMC_PASSWORD are missing")

        return management_configured and bmc_configured
    
    def ensure_connected(self) -> None:
        if not self._ucsc_handle:
            logger.info(f"Connecting to UCS central at {self.credentials['central_ip']}")
            try:
                from ucscsdk.ucschandle import UcscHandle
                from ucsmsdk.ucshandle import UcsHandle
                
                self._ucsc_handle = UcscHandle(
                    self.credentials['central_ip'],
                    self.credentials['central_username'],
                    self.credentials['central_password']
                )
                
                self._ucsc_handle.login()
                self._UcsHandle = UcsHandle
                
                logger.info("Successfully connected to UCS central")
            except ImportError as e:
                logger.error("UCS SDK is not installed. Please install ucscsdk and ucsmsdk packages.")
                raise
            except Exception as e:
                logger.error(f"Failed to connect to UCS central: {e}")
                raise
        
    def get_server_info(self, server_name: str) -> Tuple[Optional[str], Optional[str]]:
        self.ensure_connected()
        
        if self._cache is None:
            self._cache = self._ucsc_handle.query_classid("lsServer")
        
        for server in self._cache:
            if server.name.upper() == server_name.upper():
                domain = server.domain
                ucsm_handle = None 
                
                try:
                    ucsm_handle = self._UcsHandle(
                        domain,
                        self.credentials['manager_username'],
                        self.credentials['manager_password']
                    ) 
                    ucsm_handle.login()
                    
                    server_details = self._ucsc_handle.query_dn(server.dn)
                    if not server_details:
                        continue
                    
                    kvm_ip = self._extract_ucs_management_ip(ucsm_handle, server_details)

                    mac_address = self._extract_ucs_mac_address(ucsm_handle, server_details)

                    if mac_address and kvm_ip:
                        return mac_address, kvm_ip
                    
                finally:
                    if ucsm_handle:
                        try:
                            ucsm_handle.logout()
                        except:
                            pass
        return None, None
        
    def _extract_ucs_management_ip(self, ucsm_handle, server_details) -> str:
        mgmt_interfaces = ucsm_handle.query_children(
            in_mo=server_details,
            class_id="VnicIpV4PooledAddr"
        )
        
        for iface in mgmt_interfaces:
            if hasattr(iface, "addr") and iface.addr:
                return str(iface.addr)
        return ""
    
    def _extract_ucs_mac_address(self, ucsm_handle, server_details) -> str:
        adapters = ucsm_handle.query_children(
            in_mo=server_details,
            class_id="VnicEther"
        )
        
        if adapters:
            sorted_adapters = sorted(adapters, key=lambda x: x.name[3:])
            if sorted_adapters and hasattr(sorted_adapters[0], "addr"):
                return sorted_adapters[0].addr
        return ""
    
    def clear_cache(self):
        """Clear any cached data."""
        self._cache = None
    
    def disconnect(self): 
        if self._ucsc_handle:
            try: 
                self._ucsc_handle.logout()
                logger.info("Successfully disconnected from UCS central")
            except Exception as e:
                logger.warning(f"Error during UCS central logout: {e}")
            finally:
                self._ucsc_handle = None
                
            
            