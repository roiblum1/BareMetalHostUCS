import asyncio
import base64
import os
from datetime import datetime
from typing import Any, Dict, List

import kubernetes
from kubernetes import client

from src.config import MAX_AVAILABLE_SERVERS, BUFFER_CHECK_INTERVAL, buffer_logger
from src.yaml_generators import generate_baremetal_host, generate_bmc_secret

# Initialize Kubernetes clients
custom_api = client.CustomObjectsApi()
core_v1 = client.CoreV1Api()

# Buffer management
bmh_buffer_lock = asyncio.Lock()


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
        
        if not mac_address or not ipmi_address:
            buffer_logger.error(f"Missing server info for buffered generator {name}")
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
        
        # Create BMC Secret
        bmc_secret = generate_bmc_secret(
            name=name,
            namespace=target_namespace,
            username=ipmi_username,
            password=ipmi_password
        )
        
        try:
            core_v1.create_namespaced_secret(
                namespace=target_namespace,
                body=bmc_secret
            )
            buffer_logger.info(f"Created BMC secret: {name}-bmc-secret")
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 409:
                buffer_logger.debug(f"BMC secret already exists: {name}-bmc-secret")
            else:
                raise
        
        # Create BareMetalHost
        bmh = generate_baremetal_host(
            name=name,
            namespace=target_namespace,
            mac_address=mac_address,
            ipmi_address=ipmi_address,
            ipmi_username=ipmi_username,
            ipmi_password=ipmi_password,
            infra_env=infra_env,
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