import asyncio
import base64
import os
from datetime import datetime
from typing import Any, Dict, List
import kubernetes
from kubernetes import client

from yaml_generators import YamlGenerator
from openshift_utils import OpenShiftUtils
from unified_server_client import UnifiedServerClient
from config import buffer_logger, MAX_AVAILABLE_SERVERS, BUFFER_CHECK_INTERVAL

class BufferManager:
    def __init__(self, custom_api: client.CustomObjectsApi = None, core_v1: client.CoreV1Api = None):
        self.custom_api = custom_api or client.CustomObjectsApi()
        self.core_v1 = core_v1 or client.CoreV1Api()
        self.bmh_buffer_lock = asyncio.Lock()
        self.buffer_logger = buffer_logger
        self.MAX_AVAILABLE_SERVERS = MAX_AVAILABLE_SERVERS
        self.BUFFER_CHECK_INTERVAL = BUFFER_CHECK_INTERVAL 
    
    async def get_available_baremetal_hosts(self) -> List[Dict[str, Any]]:
        self.buffer_logger.debug("Querying for available BareMetalHosts")
        try:
            bmhs = self.custom_api.list_cluster_custom_object(
                group="metal3.io",
                version="v1alpha1",
                plural="baremetalhosts"
            )
            available_bmhs = []
            for bmh in bmhs.get("items", []):
                status = bmh.get("status", {})
                provisioning_state = status.get("provisioning", {}).get("state", "") 
                operational_status = status.get("operationalStatus", "")
                if (provisioning_state in ["", "provisioning", "registering"] and operational_status != "detached" and not status.get("provisioning", {}).get("consumer")):
                    available_bmhs.append(bmh)
                    self.buffer_logger.debug(f"BMH {bmh['metadata']['name']} is available (state: {provisioning_state}, operationalStatus: {operational_status})")
                else:
                    self.buffer_logger.debug(f"BMH {bmh['metadata']['name']} is not available (state: {provisioning_state}, operationalStatus: {operational_status})")  
            self.buffer_logger.info(f"Found {len(available_bmhs)} available BareMetalHosts")
            return available_bmhs
        except Exception as e:
            self.buffer_logger.error(f"Error querying BareMetalHosts: {str(e)}")
            if hasattr(e, 'status') and e.status == 404:
                self.buffer_logger.error("BareMetalHost CRD not found. Ensure that the Metal3 operator is installed.")
                return []
            raise
    
    async def get_buffered_generators(self) -> List[Dict[str, Any]]:
        self.buffer_logger.debug("Querying for buffered Generators")
        try:
            bmhgens = self.custom_api.list_cluster_custom_object(
                group="infra.example.com",
                version="v1alpha1",
                plural="baremetalhostgenerators"
            )
            buffered = []
            
            for bmhgen in bmhgens.get("items", []):
                status = bmhgen.get("status", {})
                if status.get("phase") == "Buffered":
                    buffered.append(bmhgen)
                    self.buffer_logger.debug(f"Generator {bmhgen['metadata']['name']} is buffered")
            self.buffer_logger.info(f"Found {len(buffered)} buffered Generators")
            return buffered
        except Exception as e:
            self.buffer_logger.error(f"Error querying BareMetalHostGenerators: {str(e)}")
            if hasattr(e, 'status') and e.status == 404:
                self.buffer_logger.error("BareMetalHostGenerator CRD not found. Ensure that the custom operator is installed.")
                return []
            raise
    
    async def process_buffered_generator(self, bmhgen: Dict[str, Any], unified_client: UnifiedServerClient, yaml_generator: YamlGenerator) -> None:
        """Process a single buffered BareMetalHostGenerator"""
        name = bmhgen['metadata']['name']
        namespace = bmhgen['metadata']['namespace']
        server_name = name  # Define server name here
        self.buffer_logger.info(f"Processing buffered generator: {name}")

        try:
            # Get the stored server info from status
            status = bmhgen.get('status', {})
            mac_address = status.get('macAddress')
            ipmi_address = status.get('ipmiAddress')
            server_vendor = status.get('serverVendor')

            if not server_vendor:
                annotations = bmhgen.get('metadata', {}).get('annotations', {})
                server_vendor = annotations.get('serverVendor')
                if not server_vendor:
                    # Fallback to default detection logic
                    from server_strategy import ServerTypeDetector
                    detected_type = ServerTypeDetector.detect(name)
                    server_vendor = detected_type.value.upper()

            vlan_id = status.get('vlan_id')
            if not vlan_id and server_vendor.upper() != 'DELL':
                annotations = bmhgen.get('metadata', {}).get('annotations', {})
                vlan_id = annotations.get('vlan_id')
                if not vlan_id:
                    vlan_id = ""

            if not mac_address or not ipmi_address:
                self.buffer_logger.error(f"Missing server info for buffered generator {name}")
                spec = bmhgen.get('spec', {})  # Check if spec is None
                try:
                    server_name = spec.get('name', name)
                    mac_address, ipmi_address = unified_client.get_server_info(server_name, server_vendor)
                    patch = {
                        "status": {
                            "macAddress": mac_address,
                            "ipmiAddress": ipmi_address
                        }
                    }

                    self.custom_api.patch_namespaced_custom_object_status(
                        group="infra.example.com",
                        version="v1alpha1",
                        namespace=namespace,
                        plural="baremetalhostgenerators",
                        name=name,
                        body=patch
                    )

                    OpenShiftUtils.update_bmh_status(self.custom_api, "infra.example.com", "v1alpha1", namespace, "baremetalhostgenerators", name, patch)

                except Exception as e:
                    self.buffer_logger.error(f"Error getting server info for {name}: {str(e)}")
                    patch = {
                        "status": {
                            "phase": "Failed",
                            "message": "Cannot retrieve the server info"
                        }
                    }
                    OpenShiftUtils.update_bmh_status(self.custom_api, "infra.example.com", "v1alpha1", namespace, "baremetalhostgenerators", name, patch)
                    return

            spec = bmhgen.get('spec', {})  # Check if spec is None
            target_namespace = spec.get('namespace', namespace)
            infra_env = spec.get('infraEnv')

            # Create BMC Secret (credentials come from config.py based on vendor)
            bmc_secret = yaml_generator.generate_bmc_secret(
                name=name,
                namespace=target_namespace,
                server_vendor=server_vendor
            )

            OpenShiftUtils.create_bmc_secret(self.core_v1, target_namespace, bmc_secret, server_name)

            # Create BareMetalHost
            bmh = yaml_generator.generate_baremetal_host(
                name=name,
                namespace=target_namespace,
                server_vendor=server_vendor,
                mac_address=mac_address,
                ipmi_address=ipmi_address,
                infra_env=infra_env,
                labels=spec.get('labels', {})
            )

            OpenShiftUtils.create_baremetalhost(self.custom_api, target_namespace, bmh, server_name)
            self.buffer_logger.info(f"Created BareMetalHost: {name}")

            # Update generator status to Completed
            patch = {
                "status": {
                    "phase": "Completed",
                    "message": f"Successfully created BareMetalHost {name} (released from buffer)",
                    "bmhName": name,
                    "bmhNamespace": target_namespace
                }
            }

            if server_vendor and server_vendor.upper() == 'DELL':
                nmstate_config = yaml_generator.generate_nmstate_config(
                    name=server_name,
                    namespace=target_namespace,
                    mac_address=mac_address,
                    infra_env=infra_env,
                    vlan_id=vlan_id
                )

                OpenShiftUtils.create_nmstate_config(self.custom_api, target_namespace, nmstate_config, server_name)

            OpenShiftUtils.update_bmh_status(self.custom_api, "infra.example.com", "v1alpha1", namespace, "baremetalhostgenerators", name, patch)
            self.buffer_logger.info(f"Updated generator {name} status to Completed")

        except Exception as e:
            self.buffer_logger.error(f"Error processing buffered generator {name}: {str(e)}")
            raise
    async def buffer_check_loop(self, unified_client: UnifiedServerClient, yaml_generator: YamlGenerator) -> None:
        self.buffer_logger.info("Starting buffer check loop")
        while True:
            try: 
                await asyncio.sleep(self.BUFFER_CHECK_INTERVAL)
                async with self.bmh_buffer_lock:
                    self.buffer_logger.info("Running buffer check")
                    
                    available_bmhs = await self.get_available_baremetal_hosts()
                    available_count = len(available_bmhs)
                    
                    self.buffer_logger.info(f"Available BareMetalHosts: {available_count}/{self.MAX_AVAILABLE_SERVERS}")
                    if available_count < self.MAX_AVAILABLE_SERVERS: 
                        slots_available = self.MAX_AVAILABLE_SERVERS - available_count
                        
                        buffered = await self.get_buffered_generators()
                        for i, bmhgen in enumerate(buffered[:slots_available]):
                            self.buffer_logger.info(f"Releasing buffered generator {bmhgen['metadata']['name']} from buffer")
                            await self.process_buffered_generator(bmhgen, unified_client, yaml_generator)
                            if i < slots_available - 1:
                                await asyncio.sleep(5)
                    else:
                        self.buffer_logger.info("No slots available to release servers from buffer")
            except Exception as e:
                self.buffer_logger.error(f"Error in buffer check loop: {str(e)}")
                
    async def is_to_buffer(self, server_name: str, mac_address: str, ipmi_address: str, server_vendor: str, vlan_id: str, namespace: str, name: str) -> bool:
        available_bmhs = await self.get_available_baremetal_hosts()
        available_count = len(available_bmhs)
        
        self.buffer_logger.info(f"Current available BareMetalHosts: {available_count}/{self.MAX_AVAILABLE_SERVERS}")
        if available_count >= self.MAX_AVAILABLE_SERVERS:
            self.buffer_logger.info(f"Buffering server {server_name} as buffer is full")
            try:
                status_update = {
                    "phase": "Buffered",
                    "message": f"Server buffered (available: {available_count}/{self.MAX_AVAILABLE_SERVERS})",
                    "macAddress": mac_address,
                    "ipmiAddress": ipmi_address,
                    "serverVendor": server_vendor,
                    "vlan_id": vlan_id
                }
                OpenShiftUtils.update_bmh_status(self.custom_api, "infra.example.com", "v1alpha1", namespace, "baremetalhostgenerators", name, status_update)
                self.buffer_logger.info(f"Buffering server {server_name} - limit reached")
            except Exception as e:
                self.buffer_logger.error(f"Error updating status to Buffered for {server_name}: {str(e)}")
            return True
        else:
            self.buffer_logger.info(f"Creating BareMetalHost immediately - room available {available_count} / {self.MAX_AVAILABLE_SERVERS}")
            return False