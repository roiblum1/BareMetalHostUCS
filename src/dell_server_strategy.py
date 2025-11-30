import logging
import os
from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional, Tuple, Dict, Type
import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from src.server_strategy import ServerStrategy
from src.config import dell_strategy_logger

disable_warnings(InsecureRequestWarning)
logger = dell_strategy_logger

class DellServerStrategy(ServerStrategy):
    def __init__(self, credentials: Dict[str, str]):
        self.credentials = credentials
        self.base_url = f"https://{self.credentials.get('ip')}/api" if credentials.get('ip') else None
        self._session = None
        self._auth_token = None
        self._session_id = None  # Store session ID for proper logout
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
            logger.info(f"Connecting to Dell OME at {self.base_url}")
            self._session = requests.Session()
            self._session.verify = False

            auth_url = f"{self.base_url}/SessionService/Sessions"
            auth_data = {
                "UserName": self.credentials["username"],
                "Password": self.credentials["password"],
                "SessionType": "API"
            }

            logger.debug(f"Creating session at {auth_url}")
            response = self._session.post(auth_url, json=auth_data)
            response.raise_for_status()

            # Extract auth token from header
            self._auth_token = response.headers.get("X-Auth-Token")
            if not self._auth_token:
                raise ValueError("Dell OME did not return X-Auth-Token header")

            # Extract session ID from response body or Location header
            response_data = response.json()
            self._session_id = response_data.get("Id")

            # Fallback: extract from Location header if not in body
            if not self._session_id:
                location = response.headers.get("Location", "")
                if "Sessions(" in location:
                    # Extract ID from URL like: /api/SessionService/Sessions('12345')
                    self._session_id = location.split("Sessions(")[1].rstrip(")'")

            if not self._session_id:
                logger.warning("Could not extract session ID - logout may not work properly")

            self._session.headers.update({"X-Auth-Token": self._auth_token})
            logger.info(f"Successfully connected to Dell OME (Session ID: {self._session_id})")
    
    def get_server_info(self, server_name: str) -> Tuple[Optional[str], Optional[str]]:
        self.ensure_connected()

        device_url = f"{self.base_url}/ProfileService/Profiles"
        skip = 0
        top = 130

        logger.info(f"Searching for Dell server profile: {server_name}")

        while True:
            device_url_with_pagination = f"{device_url}?$skip={skip}&$top={top}"
            response = self._session.get(device_url_with_pagination)
            response.raise_for_status()
            dell_servers_response = response.json()
            dell_servers = dell_servers_response.get("value", [])

            logger.debug(f"Retrieved {len(dell_servers)} profiles (skip={skip}, top={top})")

            for server in dell_servers:
                profile_name = server.get('ProfileName')
                if not profile_name:
                    continue

                logger.debug(f"Checking server profile: {profile_name}")

                if profile_name.upper() == server_name.upper():
                    logger.info(f"Found matching server profile: {profile_name}")
                    idrac_ip = server.get("TargetName")

                    if not idrac_ip:
                        logger.error(f"TargetName (iDRAC IP) is missing for server: {server_name}")
                        return None, None

                    logger.debug(f"iDRAC IP for {server_name}: {idrac_ip}")
                    mac_address = self._get_dell_mac_address(idrac_ip, server_name)

                    if not mac_address:
                        logger.error(f"Failed to retrieve MAC address for server: {server_name}")
                        return None, None

                    logger.info(f"Successfully retrieved server info - MAC: {mac_address}, iDRAC: {idrac_ip}")
                    return mac_address, idrac_ip

            # Check if we've reached the end of pagination
            if len(dell_servers) < top:
                total_checked = skip + len(dell_servers)
                logger.error(f"Server profile '{server_name}' not found in Dell OME after checking {total_checked} profiles. ")
                return None, None

            skip += top
            logger.debug(f"No match found in this batch, fetching next {top} profiles...")
            
    def _get_dell_mac_address(self, idrac_ip: str, server_name: str) -> Optional[str]:
        self.ensure_connected()
        device_url = f"{self.base_url}/DeviceService/Devices"
        skip = 0
        top = 40

        logger.info(f"Searching for device with iDRAC IP: {idrac_ip}")

        while True:
            device_url_with_pagination = f"{device_url}?$skip={skip}&$top={top}"
            response = self._session.get(device_url_with_pagination)
            response.raise_for_status()
            devices_response = response.json()

            devices = devices_response.get("value", [])
            logger.info(f"Retrieved {len(devices)} devices (skip={skip}, top={top})")

            # Search for device in current batch
            device = next((device for device in devices if str(device.get("DeviceName")) == str(idrac_ip)), None)

            if device:
                logger.info(f"Found matching device for iDRAC IP: {idrac_ip}")
                device_id = device.get("Id")

                inventory_details_url = f"{self.base_url}/DeviceService/Devices({device_id})/InventoryDetails('serverNetworkInterfaces')"
                logger.info(f"Fetching inventory from URL: {inventory_details_url}")

                response = self._session.get(inventory_details_url)
                response.raise_for_status()
                inventory_details_response = response.json()

                network_interfaces = inventory_details_response.get("InventoryInfo", [])
                logger.info(f"Network interfaces found: {len(network_interfaces)} for device {device_id}")

                if network_interfaces:
                    try:
                        if "data" in server_name:
                            logger.info(f"Using 'data' server logic for {server_name}")
                            last_network_interface = network_interfaces[-1]
                            last_port = last_network_interface.get("Ports", [])[-1]
                            partitions = last_port.get("Partitions", [])[-1]
                            mac_address = partitions.get("CurrentMacAddress")
                            logger.info(f"MAC address found for server {server_name}: {mac_address}")
                            return mac_address

                        first_interface = network_interfaces[0]
                        logger.info(f"First interface: {first_interface}")
                        ports = first_interface.get("Ports", [])
                        logger.info(f"Ports found: {len(ports)} ports")

                        if ports:
                            first_port = ports[0]
                            partitions = first_port.get("Partitions", [])
                            logger.info(f"Partitions found: {len(partitions)} partitions")

                            if partitions:
                                first_partition = partitions[0]
                                mac_address = first_partition.get("CurrentMacAddress")
                                logger.info(f"MAC address found for server {server_name}: {mac_address}")
                                return mac_address
                            else:
                                logger.error(f"No partitions found in first port for device {device_id}")
                        else:
                            logger.error(f"No ports found in first interface for device {device_id}")
                    except Exception as e:
                        logger.error(f"Failed to extract MAC from inventory for device {device_id}: {e}")
                        return None

                logger.error(f"No network interfaces or failed to extract MAC for device {device_id}")
                return None

            # Check if we've reached the end of pagination
            if len(devices) < top:
                logger.error(f"Device with iDRAC IP '{idrac_ip}' not found in Dell OME after checking {skip + len(devices)} devices")
                break

            skip += top
            logger.debug(f"No match found in this batch, fetching next {top} devices...")

        return None 
    def clear_cache(self):
        """Clear any cached data."""
        self._cache = None
    
    def disconnect(self):
        if self._session and self._auth_token:
            try:
                # Delete the specific session using its ID
                if self._session_id:
                    logout_url = f"{self.base_url}/SessionService/Sessions('{self._session_id}')"
                    logger.debug(f"Deleting session at: {logout_url}")
                    response = self._session.delete(logout_url)
                    response.raise_for_status()
                    logger.info(f"Successfully deleted Dell OME session {self._session_id}")
                else:
                    logger.warning("No session ID available - cannot delete session properly")
                    logger.warning("Session may remain active on Dell OME until timeout")

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    logger.info(f"Session {self._session_id} already deleted or expired")
                else:
                    logger.error(f"HTTP error during Dell OME logout: {e.response.status_code} - {e.response.text}")
            except Exception as e:
                logger.error(f"Error during Dell OME logout: {type(e).__name__}: {e}")
            finally:
                # Always close the session and clear credentials
                if self._session:
                    self._session.close()
                self._session = None
                self._auth_token = None
                self._session_id = None
                logger.debug("Dell OME session cleaned up")