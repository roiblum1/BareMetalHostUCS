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
logger = logging.getLogger('dell_strategy')

class DellServerStrategy(ServerStrategy):
    def __init__(self, credentials: Dict[str, str]):
        self.credentials = credentials 
        self.base_url = f"https://{self.credentials.get('ip')}/api" if credentials.get('ip') else None
        self._session = None
        self._auth_token = None
        self._cache = None
    
    def is_configured(self) -> bool:
        """Check if Dell OME and BMC credentials are configured."""
        # Check management system credentials
        management_configured = all([
            self.credentials.get("ip"),
            self.credentials.get("username"),
            self.credentials.get("password")
        ])

        # Check BMC credentials
        bmc_configured = all([
            os.getenv('DELL_BMC_USERNAME'),
            os.getenv('DELL_BMC_PASSWORD')
        ])

        if management_configured and not bmc_configured:
            logger.warning("Dell OME is configured but DELL_BMC_USERNAME/DELL_BMC_PASSWORD are missing")

        return management_configured and bmc_configured
    
    def ensure_connected(self) -> None:
        if not self._session or not self._auth_token:
            logger.info(f"Connecting to Dell iDRAC at {self.base_url}")
            self._session = requests.Session()
            self._session.verify = False
            
            auth_url = f"{self.base_url}/SessionService/Sessions"
            auth_data = {
                "UserName": self.credentials["username"],
                "Password": self.credentials["password"],
                "SessionType": "API"
            }
            response = self._session.post(auth_url, json=auth_data)
            response.raise_for_status()
            
            self._auth_token = response.headers.get("X-Auth-Token")
            self._session.headers.update({"X-Auth-Token": self._auth_token})
            logger.info("Successfully connected to Dell iDRAC")
    
    def get_server_info(self, server_name: str) -> Tuple[Optional[str], Optional[str]]:
        self.ensure_connected()
        
        device_url = f"{self.base_url}/ProfileService/Profiles"
        skip = 0 
        top = 130 
        
        while True:
            device_url_with_pagination = f"{device_url}?$skip={skip}&$top={top}"
            response = self._session.get(device_url_with_pagination)
            response.raise_for_status()
            dell_servers_response = response.json()
            dell_servers = dell_servers_response.get("value", [])
            logger.info(f"Searching for server: {server_name}")
            for server in dell_servers:
                logger.debug(f"Checking server profile {server.get('ProfileName')}")
                if 'ProfileName' in server:
                    profile_name_upper = server['ProfileName'].upper()
                    server_name_upper = server_name.upper()
                    if profile_name_upper == server_name_upper:
                        logger.debug(f"Found server profile: {server_name}")
                        idrac_ip = server.get("TargetName")
                        if idrac_ip is None:
                            logger.error(f"IDRAC IP is None for server: {server_name}")
                        mac_address = self._get_dell_mac_address(idrac_ip, server_name)
                        if mac_address is None:
                            logger.error(f"MAC address is None for server: {server_name}")
                        if mac_address and idrac_ip:
                            return mac_address, idrac_ip
                        else:
                            logger.error(f"Could not retrieve MAC or IDRAC IP for server: {server_name}")
            if len(dell_servers) < top:
                logger.error(f"No matching server profile found for: {server_name}")
                return None, None
            skip += top
            
    def _get_dell_mac_address(self, idrac_ip: str, server_name: str) -> Optional[str]:
        self.ensure_connected()
        device_url = f"{self.base_url}/DeviceService/Devices"
        skip = 0
        top = 40

        while True:
            device_url_with_pagination = f"{device_url}?$skip={skip}&$top={top}"
            response = self._session.get(device_url_with_pagination)
            response.raise_for_status()
            devices_response = response.json()

            devices = devices_response.get("value", [])

            device = next((device for device in devices if str(device.get("DeviceName")) == str(idrac_ip)), None)

            if device:
                logger.debug(f"The device is {device}, and his type is {type(device)}")
                device_id = device.get("Id")

                inventory_details_url = f"{self.base_url}/DeviceService/Devices({device_id})/InventoryDetails('serverNetworkInterfaces')"
                try:
                    response = self._session.get(inventory_details_url)
                    response.raise_for_status()
                    inventory_details_response = response.json()

                    network_interfaces = inventory_details_response.get("InventoryInfo", [])
                    logger.debug(f"Network interfaces found: {network_interfaces}")

                    if network_interfaces:
                        if "data" in server_name.lower():
                            last_network_interface = network_interfaces[-1]
                            last_port = last_network_interface.get("Ports", [])[-1]
                            partition = last_port.get("Partition", [])[-1]
                            mac_address = partition.get("CurrentMacAddress")
                            logger.info(f"Here is the MAC address found for server {server_name}: {mac_address}")
                            return mac_address
                        first_interface = network_interfaces[0]
                        ports = first_interface.get("Ports", [])
                        if ports:
                            first_port = ports[0]
                            partitions = first_port.get("Partition", [])
                            if partitions:
                                first_partition = partitions[0]
                                mac_address = first_partition.get("CurrentMacAddress")
                                logger.info(f"Here is the MAC address found for server {server_name}: {mac_address}")
                                return mac_address
                except Exception as e:
                    logger.error(f"Failed to retrieve inventory details for device {device_id}: {e}")
                    return None

            # Check if we've reached the end of pagination
            if len(devices) < top:
                break
            skip += top

        return None 
    
    def clear_cache(self):
        """Clear any cached data."""
        self._cache = None
    
    def disconnect(self):
        if self._session and self._auth_token:
            try:
                logout_url = f"{self.base_url}/SessionService/Sessions"
                response = self._session.delete(logout_url)
                self._session.close()
                logger.info("Successfully disconnected from Dell iDRAC")
            except Exception as e:
                logger.warning(f"Error during Dell iDRAC logout: {e}")
            finally:
                self._session = None
                self._auth_token = None