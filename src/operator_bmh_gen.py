import asyncio
import os
import subprocess
from typing import Any, Dict, Optional
import logging
import kopf
import kubernetes
from kubernetes import client, config
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from buffer_manager import BufferManager
from openshift_utils import OpenShiftUtils
from yaml_generators import YamlGenerator
from unified_server_client import UnifiedServerClient, initialize_unified_client
from config import operator_logger, buffer_logger

# Initialize YAML generator
yaml_generator = YamlGenerator()

# Load Kubernetes configuration
try:
    config.load_incluster_config()
    operator_logger.info("Loaded in-cluster Kubernetes configuration.")
except Exception as e:
    operator_logger.warning(f"Failed to load in cluster config: {e}. ")
    operator_logger.info("Falling back to kubeconfig file.")
    config.load_kube_config()

# Initialize Kubernetes clients
k8s_client = client.ApiClient()
custom_api = client.CustomObjectsApi(k8s_client)
core_api = client.CoreV1Api(k8s_client)
operator_logger.info("Kubernetes client initialized.")

# Initialize buffer manager and unified client (will be set in startup)
buffer_manager = BufferManager(custom_api, core_api)
unified_client: Optional[UnifiedServerClient] = None

# Disable SSL warnings
disable_warnings(InsecureRequestWarning)


@kopf.on.startup()
async def configure(settings: kopf.OperatorSettings, **_):
    """Configure operator settings and initialize connections"""
    operator_logger.info("Starting operator configuration.")

    # Configure kopf settings
    settings.execution.max_workers = 4
    settings.posting.enabled = False
    settings.batching.worker_limit = 1
    settings.persistence.finalizer = 'bmhgenerator.infra.example.com/finalizer'
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage()
    operator_logger.info("Operator settings configured.")

    # Test API access
    try:
        operator_logger.info("Testing API access...")
        custom_api.get_api_resources()
        operator_logger.info("Successfully accessed Kubernetes API.")

        custom_api.list_cluster_custom_object(
            group="infra.example.com",
            version="v1alpha1",
            plural="baremetalhostgenerators"
        )
        operator_logger.info("Successfully accessed BareMetalHostGenerator custom resources.")
    except Exception as e:
        operator_logger.error(f"Failed to access Kubernetes API or custom resources: {e}")

    # Initialize unified client
    global unified_client
    unified_client = initialize_unified_client()

    # Check initial available BareMetalHost count
    try:
        available_bmhs = await buffer_manager.get_available_baremetal_hosts()
        available_count = len(available_bmhs)

        if available_count > buffer_manager.MAX_AVAILABLE_SERVERS:
            operator_logger.warning(
                f"Starting with {available_count} available servers, "
                f"exceeds limit of {buffer_manager.MAX_AVAILABLE_SERVERS}."
            )
            operator_logger.warning("New servers will be buffered until available count drops below the limit.")
        else:
            operator_logger.info(
                f"Starting with {available_count}/{buffer_manager.MAX_AVAILABLE_SERVERS} available servers."
            )
    except Exception as e:
        operator_logger.error(f"Error during initial available BareMetalHost check: {e}")

    operator_logger.info("Operator configuration completed successfully.")


@kopf.daemon(
    'infra.example.com', 'v1alpha1', 'baremetalhostgenerators',
    initial_delay=10,
    cancellation_timeout=10,
)
async def buffer_check_daemon(stopped: kopf.DaemonStopped, **kwargs):
    """
    Background daemon for releasing buffered generators.

    This runs in kopf's event loop, making asyncio.Lock safe to use.
    The daemon checks every BUFFER_CHECK_INTERVAL seconds for buffered
    generators that can be released when slots become available.
    """
    buffer_logger.info("Buffer check daemon started")

    try:
        while not stopped:
            try:
                # Wait for interval or stop signal
                await asyncio.wait_for(
                    stopped.wait(),
                    timeout=buffer_manager.BUFFER_CHECK_INTERVAL
                )
                # If we get here, stopped was set
                break
            except asyncio.TimeoutError:
                # Normal timeout - time to check buffer
                pass

            # Run buffer check iteration
            try:
                stats = await buffer_manager.buffer_check_iteration(unified_client, yaml_generator)
                buffer_logger.info(
                    f"Buffer check completed: "
                    f"available={stats['available_count']}, "
                    f"buffered={stats['buffered_count']}, "
                    f"released={stats['released_count']}, "
                    f"failed={stats['failed_count']}"
                )
            except Exception as e:
                buffer_logger.error(f"Error in buffer check iteration: {e}")
                # Continue running despite errors
                await asyncio.sleep(5)

    finally:
        buffer_logger.info("Buffer check daemon stopped")


@kopf.on.create('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def create_bmh(spec: Dict[str, Any], name: str, namespace: str, annotations: Optional[Dict[str, str]], **kwargs):
    """
    Handler for creating BareMetalHost resources from BareMetalHostGenerator CRDs.

    This handler:
    1. Queries the management system for server info (MAC, IP)
    2. Checks if the server should be buffered or created immediately
    3. Creates BMC Secret, BareMetalHost, and optionally NMStateConfig
    4. Updates the generator status
    """
    operator_logger.info(f"Processing BareMetalHostGenerator: {name} in namespace: {namespace}")

    # Get or default serverName
    server_name = spec.get('serverName', name)
    target_namespace = spec.get('namespace', namespace)
    infra_env = spec.get('infraEnv')

    # If serverName was not provided in spec, patch it to make the spec explicit
    if 'serverName' not in spec:
        operator_logger.info(f"serverName not provided in spec, patching with CR name: {name}")
        try:
            patch_body = {
                "spec": {
                    "serverName": name
                }
            }
            custom_api.patch_namespaced_custom_object(
                group="infra.example.com",
                version="v1alpha1",
                namespace=namespace,
                plural="baremetalhostgenerators",
                name=name,
                body=patch_body,
                _content_type="application/merge-patch+json"
            )
            operator_logger.info(f"Successfully patched serverName to spec: {name}")
        except Exception as e:
            operator_logger.warning(f"Failed to patch serverName to spec (non-critical): {e}")
            # Continue anyway - this is just for clarity, not functionality

    metadata = kwargs.get('metadata', {})
    operator_logger.info(f"Metadata for BMHG {name}: {metadata}")

    server_vendor = annotations.get('server_vendor') if annotations else None
    vlan_id = annotations.get('vlanId') if annotations else None

    operator_logger.info(f"Server vendor annotation: {server_vendor}")

    if not infra_env:
        raise kopf.PermanentError(f"infraEnv is required in the spec of BareMetalHostGenerator {name}")

    # Update status to Processing
    status_update = {
        "phase": "Processing",
        "message": f"Looking up server {server_name} in management systems."
    }
    OpenShiftUtils.update_bmh_status(
        custom_api, "infra.example.com", "v1alpha1",
        namespace, "baremetalhostgenerators", name, status_update
    )

    try:
        operator_logger.info(f"Searching for server info: {server_name}")
        mac_address, ip_address = unified_client.get_server_info(server_name, server_vendor)

        if not mac_address or not ip_address:
            raise kopf.PermanentError(f"Server {server_name} not found in any management system")

        operator_logger.info(f"Found server {server_name} with MAC: {mac_address}, IP: {ip_address}")

        if not server_vendor:
            detected_type = unified_client._detector.detect(server_name)
            server_vendor = detected_type.name
        operator_logger.info(f"Final server vendor: {server_vendor}")

        # Check if should buffer or create immediately
        if await buffer_manager.is_to_buffer(
            server_name,
            mac_address,
            ip_address,
            server_vendor,
            vlan_id,
            namespace,
            name
        ):
            # Server was buffered, status was updated by is_to_buffer
            return

        # Create resources immediately
        bmh_secret = yaml_generator.generate_bmc_secret(
            name=server_name,
            namespace=target_namespace,
            server_vendor=server_vendor
        )
        OpenShiftUtils.create_bmc_secret(core_api, target_namespace, bmh_secret, server_name)

        bmh = yaml_generator.generate_baremetal_host(
            name=server_name,
            namespace=target_namespace,
            server_vendor=server_vendor,
            mac_address=mac_address,
            ipmi_address=ip_address,
            infra_env=infra_env,
            labels=spec.get('labels')
        )
        OpenShiftUtils.create_baremetalhost(custom_api, target_namespace, bmh, server_name)

        # Create NMStateConfig for Dell servers
        if server_vendor:
            operator_logger.info(f"The VLAN ID is: {vlan_id}")
            if server_vendor.upper() == "DELL" and vlan_id:
                nmstate_config = yaml_generator.generate_nmstate_config(
                    name=server_name,
                    namespace=target_namespace,
                    macAddress=mac_address,
                    infra_env=infra_env,
                    vlan_id=vlan_id
                )
                OpenShiftUtils.create_nmstate_config(custom_api, target_namespace, nmstate_config, server_name)

        # Update status to Completed
        status_update = {
            "phase": "Completed",
            "message": f"Successfully created BareMetalHost {server_name}",
            "bmhName": server_name,
            "bmhNamespace": target_namespace,
            "macAddress": mac_address,
            "ipmiAddress": ip_address,
            "serverVendor": server_vendor,
            "vlanId": vlan_id
        }

        OpenShiftUtils.update_bmh_status(
            custom_api, "infra.example.com", "v1alpha1",
            namespace, "baremetalhostgenerators", name, status_update
        )
        operator_logger.info(f"Successfully completed BareMetalHost creation for: {server_name}")

    except Exception as e:
        operator_logger.error(f"Error processing BareMetalHostGenerator {name}: {e}")
        status_update = {
            "phase": "Error",
            "message": str(e)
        }
        # Preserve MAC/IP if they were retrieved before error
        if 'mac_address' in locals() and mac_address:
            status_update["macAddress"] = mac_address
        if 'ip_address' in locals() and ip_address:
            status_update["ipmiAddress"] = ip_address
        if 'server_vendor' in locals() and server_vendor:
            status_update["serverVendor"] = server_vendor

        OpenShiftUtils.update_bmh_status(
            custom_api, "infra.example.com", "v1alpha1",
            namespace, "baremetalhostgenerators", name, status_update
        )
        raise kopf.PermanentError(f"Failed to create BareMetalHost for {server_name}: {e}")


@kopf.on.update('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def update_bmh(spec, status, name, **kwargs):
    """Handler for updates to BareMetalHostGenerator - currently ignored as resource is immutable"""
    operator_logger.info(f"BareMetalHostGenerator {name} update ignored - resource is immutable.")
    operator_logger.debug(f"Current status: {status}")
    return status


@kopf.on.delete('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def delete_bmh(spec, name, namespace, status, **kwargs):
    """
    Handler for deleting BareMetalHostGenerator CRDs.

    This handler cleans up associated resources:
    - NMStateConfig (for Dell servers)
    - BMC Secret
    - BareMetalHost
    """
    operator_logger.info(f"Processing deletion of BareMetalHost Generator: {name}")

    if status.get('bmhName') and status.get('bmhNamespace'):
        bmh_name = status['bmhName']
        bmh_namespace = status['bmhNamespace']
        server_vendor = status.get('serverVendor')
        vlan_id = status.get('vlanId')

        try:
            # Delete NMStateConfig if exists (Dell servers only)
            if server_vendor and server_vendor.upper() == 'DELL':
                nmstate_config_name = bmh_name
                OpenShiftUtils.delete_nmstate_config(custom_api, bmh_namespace, nmstate_config_name)
                operator_logger.info(
                    f"Deleted NMStateConfig: {nmstate_config_name} in namespace: {bmh_namespace}"
                )

            # Delete BMC Secret
            bmc_secret_name = f"{str(server_vendor).lower()}-cred-{bmh_name}"
            OpenShiftUtils.delete_bmc_secret(core_api, bmh_namespace, bmc_secret_name)
            operator_logger.info(
                f"Deleted BMC Secret: {bmc_secret_name} in namespace: {bmh_namespace}"
            )

            # Delete BareMetalHost
            OpenShiftUtils.delete_baremetalhost(custom_api, bmh_namespace, bmh_name)
            operator_logger.info(
                f"Deleted BareMetalHost: {bmh_name} in namespace: {bmh_namespace}"
            )

        except Exception as e:
            operator_logger.error(f"Error deleting BareMetalHost and related resources: {str(e)}")
            raise kopf.PermanentError(f"Error deleting BareMetalHost and related resources: {str(e)}")
    else:
        operator_logger.warning(f"No associated BareMetalHost found for generator: {name}")


@kopf.on.cleanup()
async def cleanup_fn(**kwargs):
    """
    Cleanup function called on operator shutdown.

    This handler:
    - Requests shutdown of buffer manager
    - Disconnects from server management systems
    """
    operator_logger.info("Operator shutting down, cleaning up resources")

    # Request buffer manager shutdown
    buffer_manager.request_shutdown()

    # Disconnect from server management systems
    if unified_client:
        try:
            unified_client.disconnect()
            operator_logger.info("Disconnected from server management systems")
        except Exception as e:
            operator_logger.warning(f"Error disconnecting from server management systems: {e}")

    operator_logger.info("Cleanup completed")


if __name__ == "__main__":
    operator_logger.info("Starting BareMetalHost Generator Operator with Buffering")
    operator_logger.info(f"Process PID: {os.getpid()}")
    operator_logger.info(f"Python version: {subprocess.check_output(['python', '--version']).decode().strip()}")

    try:
        kopf.run()
    except Exception as e:
        operator_logger.critical(f"Operator crashed: {str(e)}")
        operator_logger.exception("Full crash details:")
        raise
