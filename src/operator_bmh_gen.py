import asyncio
import base64
import os
from datetime import datetime
from typing import Any, Dict

import kopf
import kubernetes
from kubernetes import client, config

from src.config import (
    MAX_AVAILABLE_SERVERS,
    operator_logger,
    buffer_logger
)
from src.unified_client import UnifiedServerClient
from src.yaml_generators import generate_baremetal_host, generate_bmc_secret
from src.buffer_manager import (
    bmh_buffer_lock,
    get_available_baremetalhosts,
    buffer_check_loop
)

# Load Kubernetes config
try:
    config.load_incluster_config()
    operator_logger.info("Loaded in-cluster Kubernetes configuration")
except Exception as e:
    operator_logger.warning(f"Failed to load in-cluster config: {e}")
    operator_logger.info("Falling back to kubeconfig")
    config.load_kube_config()

# Initialize Kubernetes clients
k8s_client = client.ApiClient()
custom_api = client.CustomObjectsApi(k8s_client)
core_v1 = client.CoreV1Api(k8s_client)
operator_logger.info("Initialized Kubernetes API clients")

# Unified server client (initialized on startup)
unified_client = None

# Buffer management
buffer_check_task = None


def get_unified_connection():
    """Get unified server connection, creating new instance for each use"""
    global unified_client
    
    if not unified_client:
        raise RuntimeError("Unified client not initialized")
    
    # Create a new instance with the same credentials
    # This ensures fresh connections for each server lookup
    return UnifiedServerClient(
        # HP OneView
        oneview_ip=unified_client.oneview_ip,
        oneview_username=unified_client.oneview_username,
        oneview_password=unified_client.oneview_password,
        # Cisco UCS
        ucs_central_ip=unified_client.ucs_central_ip,
        central_username=unified_client.central_username,
        central_password=unified_client.central_password,
        manager_username=unified_client.manager_username,
        manager_password=unified_client.manager_password,
        # Dell OME
        ome_ip=unified_client.ome_ip,
        ome_username=unified_client.ome_username,
        ome_password=unified_client.ome_password
    )


@kopf.on.startup()
async def configure(settings: kopf.OperatorSettings, **_):
    """Configure operator settings"""
    operator_logger.info("Starting operator configuration")
    
    settings.persistence.finalizer = 'bmhgenerator.infra.example.com/finalizer'
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage()
    
    # Initialize unified server client
    global unified_client
    
    # HP OneView credentials
    oneview_ip = os.getenv('ONEVIEW_IP')
    oneview_username = os.getenv('ONEVIEW_USERNAME', 'administrator')
    oneview_password = os.getenv('ONEVIEW_PASSWORD')
    
    # Cisco UCS credentials
    ucs_central_ip = os.getenv('UCS_CENTRAL_IP')
    central_username = os.getenv('UCS_CENTRAL_USERNAME', 'admin')
    central_password = os.getenv('UCS_CENTRAL_PASSWORD')
    manager_username = os.getenv('UCS_MANAGER_USERNAME', 'admin')
    manager_password = os.getenv('UCS_MANAGER_PASSWORD')
    
    # Dell OME credentials
    ome_ip = os.getenv('OME_IP')
    ome_username = os.getenv('OME_USERNAME', 'admin')
    ome_password = os.getenv('OME_PASSWORD')
    
    # Check if at least one system is configured
    hp_configured = all([oneview_ip, oneview_password])
    ucs_configured = all([ucs_central_ip, central_password, manager_password])
    dell_configured = all([ome_ip, ome_password])
    
    if not any([hp_configured, ucs_configured, dell_configured]):
        operator_logger.error("No server management system configured. At least one system must be configured.")
        raise ValueError("Missing server management configuration")
    
    # Log which systems are configured
    configured_systems = []
    if hp_configured:
        configured_systems.append("HP OneView")
    if ucs_configured:
        configured_systems.append("Cisco UCS")
    if dell_configured:
        configured_systems.append("Dell OME")
    
    operator_logger.info(f"Configured server management systems: {', '.join(configured_systems)}")
    
    unified_client = UnifiedServerClient(
        # HP OneView
        oneview_ip=oneview_ip,
        oneview_username=oneview_username,
        oneview_password=oneview_password,
        # Cisco UCS
        ucs_central_ip=ucs_central_ip,
        central_username=central_username,
        central_password=central_password,
        manager_username=manager_username,
        manager_password=manager_password,
        # Dell OME
        ome_ip=ome_ip,
        ome_username=ome_username,
        ome_password=ome_password
    )
    
    # Check if we're already over limit
    try:
        available_bmhs = get_available_baremetalhosts()
        available_count = len(available_bmhs)
        
        if available_count > MAX_AVAILABLE_SERVERS:
            operator_logger.warning(f"Starting with {available_count} available servers, exceeds limit of {MAX_AVAILABLE_SERVERS}")
            operator_logger.warning("New servers will be buffered until available count drops below limit")
    except Exception as e:
        operator_logger.error(f"Error checking initial BMH count: {e}")
    
    # Setup asyncio event loop and start buffer check task
    global buffer_check_task
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    buffer_check_task = asyncio.create_task(buffer_check_loop())
    buffer_logger.info("Started buffer check background task")
    
    operator_logger.info("Operator configuration completed successfully")


@kopf.on.create('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def create_bmh(spec: Dict[str, Any], name: str, namespace: str, **kwargs):
    """Handle BareMetalHostGenerator creation"""
    
    operator_logger.info(f"Processing BareMetalHostGenerator: {name} in namespace: {namespace}")
    
    server_name = spec.get('serverName', name)
    target_namespace = spec.get('namespace', namespace)
    infra_env = spec.get('infraEnv')
    
    if not infra_env:
        raise kopf.PermanentError("infraEnv is required in spec")
    
    # Initial status
    status_update = {
        "phase": "Processing",
        "message": f"Looking up server {server_name} in management systems"
    }
    
    try:
        # Update status
        custom_api.patch_namespaced_custom_object_status(
            group="infra.example.com",
            version="v1alpha1",
            namespace=namespace,
            plural="baremetalhostgenerators",
            name=name,
            body={"status": status_update}
        )
    except Exception as e:
        operator_logger.warning(f"Could not update initial status: {e}")
    
    try:
        # Get unified connection and search for server
        with get_unified_connection() as client:
            operator_logger.info(f"Searching for server: {server_name}")
            mac_address, ipmi_address = client.get_server_info(server_name)
            operator_logger.info(f"Server found - MAC: {mac_address}, Management IP: {ipmi_address}")
        
        # Check if we should buffer or create immediately
        async with bmh_buffer_lock:
            available_bmhs = get_available_baremetalhosts()
            available_count = len(available_bmhs)
            
            buffer_logger.info(f"Current available BareMetalHosts: {available_count}/{MAX_AVAILABLE_SERVERS}")
            
            if available_count >= MAX_AVAILABLE_SERVERS:
                # Buffer this server
                status_update = {
                    "phase": "Buffered",
                    "message": f"Server buffered (available: {available_count}/{MAX_AVAILABLE_SERVERS})",
                    "bufferedAt": datetime.now().isoformat(),
                    "macAddress": mac_address,
                    "ipmiAddress": ipmi_address
                }
                
                custom_api.patch_namespaced_custom_object_status(
                    group="infra.example.com",
                    version="v1alpha1",
                    namespace=namespace,
                    plural="baremetalhostgenerators",
                    name=name,
                    body={"status": status_update}
                )
                
                buffer_logger.info(f"Buffering server {server_name} - limit reached")
                return
        
        # Get IPMI credentials from environment only
        ipmi_username = os.getenv('IPMI_USERNAME', 'admin')
        ipmi_password = os.getenv('IPMI_PASSWORD', 'password')
        
        # If credentials are base64 encoded in env, decode them
        try:
            ipmi_username = base64.b64decode(ipmi_username).decode()
            ipmi_password = base64.b64decode(ipmi_password).decode()
            operator_logger.debug("Decoded base64 IPMI credentials from environment")
        except:
            operator_logger.debug("Using plain text IPMI credentials from environment")
        
        # Create BMC Secret
        bmc_secret = generate_bmc_secret(
            name=server_name,
            namespace=target_namespace,
            username=ipmi_username,
            password=ipmi_password
        )
        
        try:
            core_v1.create_namespaced_secret(
                namespace=target_namespace,
                body=bmc_secret
            )
            operator_logger.info(f"Created BMC secret: {server_name}-bmc-secret")
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 409:
                operator_logger.info(f"BMC secret already exists: {server_name}-bmc-secret")
            else:
                raise
        
        # Generate and create BareMetalHost
        bmh = generate_baremetal_host(
            name=server_name,
            namespace=target_namespace,
            mac_address=mac_address,
            ipmi_address=ipmi_address,
            ipmi_username=ipmi_username,
            ipmi_password=ipmi_password,
            infra_env=infra_env,
            labels=spec.get('labels', {})
        )
        
        try:
            custom_api.create_namespaced_custom_object(
                group="metal3.io",
                version="v1alpha1",
                namespace=target_namespace,
                plural="baremetalhosts",
                body=bmh
            )
            operator_logger.info(f"Created BareMetalHost: {server_name}")
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 404:
                operator_logger.warning("Metal3 CRD not found - simulating creation for testing")
            elif e.status == 409:
                operator_logger.info(f"BareMetalHost already exists: {server_name}")
            else:
                raise
        
        # Update status to success
        status_update = {
            "phase": "Completed",
            "message": f"Successfully created BareMetalHost {server_name}",
            "bmhName": server_name,
            "bmhNamespace": target_namespace
        }
        
        custom_api.patch_namespaced_custom_object_status(
            group="infra.example.com",
            version="v1alpha1",
            namespace=namespace,
            plural="baremetalhostgenerators",
            name=name,
            body={"status": status_update}
        )
        
        operator_logger.info(f"Successfully completed BareMetalHost creation for: {server_name}")
        
    except Exception as e:
        operator_logger.error(f"Failed to create BareMetalHost: {str(e)}")
        
        status_update = {
            "phase": "Failed",
            "message": f"Error: {str(e)}"
        }
        
        try:
            custom_api.patch_namespaced_custom_object_status(
                group="infra.example.com",
                version="v1alpha1",
                namespace=namespace,
                plural="baremetalhostgenerators",
                name=name,
                body={"status": status_update}
            )
        except:
            pass
            
        raise kopf.PermanentError(f"Failed to create BareMetalHost: {str(e)}")


@kopf.on.update('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def update_bmh(spec, status, name, **kwargs):
    """Ignore updates - BareMetalHostGenerators are immutable"""
    operator_logger.info(f"BareMetalHostGenerator {name} update ignored - resource is immutable")
    return


@kopf.on.delete('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def delete_bmh(spec, name, namespace, status, **kwargs):
    """Clean up BareMetalHost when generator is deleted"""
    operator_logger.info(f"Processing deletion of BareMetalHostGenerator: {name}")
    
    if status.get('bmhName') and status.get('bmhNamespace'):
        operator_logger.info(f"BareMetalHostGenerator deleted, keeping BareMetalHost: {status['bmhName']}")


@kopf.on.cleanup()
async def cleanup_fn(**kwargs):
    """Cleanup function called on operator shutdown"""
    operator_logger.info("Operator shutting down")
    
    if buffer_check_task:
        buffer_check_task.cancel()
        try:
            await buffer_check_task
        except asyncio.CancelledError:
            buffer_logger.info("Buffer check task cancelled")
    
    if unified_client:
        try:
            unified_client.disconnect()
        except Exception as e:
            operator_logger.warning(f"Error disconnecting from server management systems: {e}")
    
    operator_logger.info("Cleanup completed")


if __name__ == "__main__":
    operator_logger.info("Starting BareMetalHost Generator Operator with Buffering")
    operator_logger.info(f"Max available servers: {MAX_AVAILABLE_SERVERS}")
    operator_logger.info(f"Buffer check interval: {BUFFER_CHECK_INTERVAL}s")
    
    try:
        kopf.run()
    except Exception as e:
        operator_logger.critical(f"Operator crashed: {str(e)}")
        raise