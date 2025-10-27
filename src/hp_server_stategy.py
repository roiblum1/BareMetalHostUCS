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
logger = logging.getLogger('hp_strategy')

class HPServerStrategy(ServerStrategy):
    
    def __init__(self, credentials: Dict[str, str]):
        self.credentials = credentials
        self.base_url = f"https://{self.credentials.get('ip')}" if credentials.get('ip') else None
        self._session = None
        self._auth_token = None
        self._cache = None
        
    
    def is_configured(self) -> bool:
        """Check if HP OneView and BMC credentials are configured."""
        # Check management system credentials
        management_configured = all([
            self.credentials.get("ip"),
            self.credentials.get("username"),
            self.credentials.get("password")
        ])

        # Check BMC credentials
        bmc_configured = all([
            os.getenv('HP_BMC_USERNAME'),
            os.getenv('HP_BMC_PASSWORD')
        ])

        if management_configured and not bmc_configured:
            logger.warning("HP OneView is configured but HP_BMC_USERNAME/HP_BMC_PASSWORD are missing")

        return management_configured and bmc_configured
    
    def ensure_connected(self):
        if not self._session or not self._auth_token:
            logger.info(f"Connecting to OneView at {self.base_url}")
            self._session = requests.Session()
            self._session.verify = False
            
            auth_url = f"{self.base_url}/rest/login-sessions"
            auth_data = {
                "userName": self.credentials["username"],
                "password": self.credentials["password"]
            }
            
            headers = {"Content-Type": "application/json", "X-API-Version": "2000"}
            
            response = self._session.post(auth_url, json=auth_data, headers=headers)
            response.raise_for_status()
            
            self._auth_token = response.json().get("sessionID")
            self._session.headers.update({"Auth": self._auth_token, "X-API-Version": "2000"})
            
            logger.info("Successfully connected to OneView")
    
    def get_server_info(self, server_name: str) -> Tuple[Optional[str], Optional[str]]:
        self.ensure_connected()
        
        self._cache = []
        next_page_uri = f"{self.base_url}/rest/server-profiles?count=-1"
        
        while next_page_uri:
            try:
                response = self._session.get(next_page_uri)
                response.raise_for_status()
                page_data = response.json()
            except Exception as e:
                logger.error(f"Failed to retrieve server profiles: {e}")
                return None, None
            
            self._cache.extend(page_data.get("members", []))
            next_page_uri = page_data.get("nextPageUri")
            if next_page_uri:
                next_page_uri = f"{self.base_url}{next_page_uri}"
        
        for server in self._cache:
            server_name_attr = server.get("name")
            server_serial_number = server.get("serialNumber")
            
            if (server_name and server_name_attr and server_name.upper() == server_name_attr.upper()) or \
               (server_name and server_serial_number and server_name.upper() == server_serial_number.upper()):
                server_hardware_uri  = server.get("serverHardwareUri")
                if not server_hardware_uri.startswith(self.base_url):
                    server_hardware_uri = f"{self.base_url}{server_hardware_uri}"
                try:
                    response = self._session.get(server_hardware_uri)
                    response.raise_for_status()
                    server_hardware = response.json()
                except Exception as e:
                    logger.error(f"Failed to retrieve server hardware details: {e}")
                    return None, None
                
                ilo_ip = self._extract_hp_management_ip(server_hardware)
                if (not ilo_ip):
                    logger.error(f"Could not find iLO IP address for server {server_name}")
                    return None, None
                mac_address = self._extract_hp_mac_address(server_hardware)
                if (not mac_address):
                    logger.error(f"Could not find MAC address for server {server_name}")
                    return None, None
                if mac_address and ilo_ip:
                    return mac_address, ilo_ip 
        logger.error(f"Server {server_name} not found in OneView")
        return None, None
    
    def _extract_hp_management_ip(self, server):
        if 'mpHostInfo' in server and 'mpIpAddresses' in server['mpHostInfo']:
            for ip_address in server['mpHostInfo']['mpIpAddresses']:
                if ip_address['type'] == 'Static':
                    return ip_address['address']
        return None
    
    def _extract_hp_mac_address(self, server_hardware):
        port_map =  server_hardware.get("portMap", {})
        device_slots = port_map.get("deviceSlots", [])
        
        for slot in device_slots:
            for port in slot.get("physicalPorts", []):
                if port.get("type") == "Ethernet" and not port.get('mac', '').startswith('00'):
                    return port.get("mac")
        return None
    
    def clear_cache(self):
        self._cache = None

    def disconnect(self):
        if (self._session and self._auth_token):
            try:
                logout_url = f"{self.base_url}/rest/login-sessions"
                self._session.delete(logout_url)
                self._session.close()
                logger.info("Successfully disconnected from OneView")
            except Exception as e:
                logger.error(f"Failed to disconnect from OneView: {e}")
            finally:
                self._session = None
                self._auth_token = None
                    