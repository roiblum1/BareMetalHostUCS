import asyncio
import os
import subprocess
import time
from typing import Any, Dict, Optional
import logging
import kopf
import kubernetes
from kubernetes import client, config
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from src.buffer_manager import BufferManager
from src.openshift_utils import OpenShiftUtils
from src.yaml_generators import YamlGenerator
from src.unified_server_client import UnifiedServerClient, initialize_unified_client
from src.config import operator_logger, buffer_logger, BUFFER_CHECK_INTERVAL, BMHGenCRD, BMHCRD, Phase

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

# Background task for buffer checking (created in startup)
_buffer_check_task: Optional[asyncio.Task] = None

# Disable SSL warnings
disable_warnings(InsecureRequestWarning)


@kopf.on.startup()
async def configure(settings: kopf.OperatorSettings, **_):
    """Configure operator settings and initialize connections"""
    operator_logger.info("Starting operator configuration.")

    # Configure kopf settings
    # Serial processing (1 worker) to prevent buffer race conditions
    # This ensures strict enforcement of MAX_AVAILABLE_SERVERS limit
    settings.execution.max_workers = 1  # Process CRs one at a time
    settings.execution.idle_timeout = 60.0  # Timeout for idle handlers

    settings.posting.enabled = False

    # Batching settings - single worker for strict serialization
    settings.batching.worker_limit = 1  # Process one CR at a time to avoid buffer races
    settings.batching.batch_window = 0.5  # Short batch window for responsiveness
    settings.batching.idle_timeout = 5.0  # Timeout for idle batches
    
    # Watch settings - handle large numbers of resources
    settings.watching.server_timeout = 60.0  # Watch connection timeout
    settings.watching.client_timeout = 60.0  # Client timeout
    settings.watching.reconnect_backoff = 1.0  # Reconnect backoff
    
    settings.persistence.finalizer = BMHGenCRD.FINALIZER
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage()

    operator_logger.info("Operator settings configured for serial processing with strict buffer control.")

    # Test API access
    try:
        operator_logger.info("Testing API access...")
        custom_api.get_api_resources()
        operator_logger.info("Successfully accessed Kubernetes API.")

        custom_api.list_cluster_custom_object(
            group=BMHGenCRD.GROUP,
            version=BMHGenCRD.VERSION,
            plural=BMHGenCRD.PLURAL
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

    # Create background task for buffer checking
    global _buffer_check_task
    _buffer_check_task = asyncio.create_task(_buffer_check_loop(), name="buffer-check-loop")
    operator_logger.info("Started background buffer check task")


async def _buffer_check_loop():
    """
    Background task that periodically checks for buffered servers to release.

    This runs as a single global task created in startup, ensuring:
    - Only ONE task runs regardless of number of resources
    - asyncio.Lock works correctly (created in same event loop)
    - Graceful cancellation on operator shutdown
    """
    buffer_logger.info("Buffer check loop starting, waiting 10 seconds before first check...")
    await asyncio.sleep(10)

    while True:
        try:
            # Skip if unified client not initialized yet
            if unified_client is None:
                buffer_logger.warning("Unified client not initialized, skipping buffer check")
                await asyncio.sleep(BUFFER_CHECK_INTERVAL)
                continue

            # Perform buffer check iteration
            stats = await buffer_manager.buffer_check_iteration(unified_client, yaml_generator)
            buffer_logger.info(
                f"Buffer check completed: "
                f"available={stats['available_count']}, "
                f"buffered={stats['buffered_count']}, "
                f"released={stats['released_count']}, "
                f"failed={stats['failed_count']}"
            )

        except asyncio.CancelledError:
            buffer_logger.info("Buffer check loop cancelled, exiting gracefully")
            raise  # Re-raise to properly exit the task
        except Exception as e:
            buffer_logger.error(f"Error in buffer check iteration: {e}", exc_info=True)
            # Continue loop on errors - don't crash the background task

        # Wait before next iteration
        await asyncio.sleep(BUFFER_CHECK_INTERVAL)


@kopf.on.create(BMHGenCRD.GROUP, BMHGenCRD.VERSION, BMHGenCRD.PLURAL)
async def create_bmh(spec: Dict[str, Any], name: str, namespace: str, annotations: Optional[Dict[str, str]], patch: kopf.Patch, **kwargs):
    """
    Handler for creating BareMetalHost resources from BareMetalHostGenerator CRDs.

    This handler:
    1. Queries the management system for server info (MAC, IP)
    2. Checks if the server should be buffered or created immediately
    3. Creates BMC Secret, BareMetalHost, and optionally NMStateConfig
    4. Updates the generator status
    """
    handler_start_time = time.time()
    operator_logger.info(f"[CREATE] Starting handler for BareMetalHostGenerator: {name} in namespace: {namespace}")

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
            # Run blocking call in thread pool to avoid blocking event loop
            await asyncio.to_thread(
                custom_api.patch_namespaced_custom_object,
                group=BMHGenCRD.GROUP,
                version=BMHGenCRD.VERSION,
                namespace=namespace,
                plural=BMHGenCRD.PLURAL,
                name=name,
                body=patch_body
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
        # Update status before raising error using kopf's patch mechanism
        patch.status["phase"] = Phase.FAILED
        patch.status["message"] = f"infraEnv is required in the spec of BareMetalHostGenerator {name}"
        raise kopf.PermanentError(f"infraEnv is required in the spec of BareMetalHostGenerator {name}")

    # Update status to Processing
    patch.status["phase"] = Phase.PROCESSING
    patch.status["message"] = f"Looking up server {server_name} in management systems."

    try:
        operator_logger.info(f"Searching for server info: {server_name}")
        # Run blocking network call in thread pool to avoid blocking event loop
        mac_address, ip_address = await asyncio.to_thread(
            unified_client.get_server_info,
            server_name,
            server_vendor
        )

        if not mac_address or not ip_address:
            # Update status before raising error
            patch.status["phase"] = Phase.FAILED
            patch.status["message"] = f"Server {server_name} not found in any management system"
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
        # Run blocking Kubernetes API call in thread pool
        await asyncio.to_thread(
            OpenShiftUtils.create_bmc_secret,
            core_api, target_namespace, bmh_secret, server_name
        )

        bmh = yaml_generator.generate_baremetal_host(
            name=server_name,
            namespace=target_namespace,
            server_vendor=server_vendor,
            mac_address=mac_address,
            ipmi_address=ip_address,
            infra_env=infra_env,
            labels=spec.get('labels')
        )
        # Run blocking Kubernetes API call in thread pool
        await asyncio.to_thread(
            OpenShiftUtils.create_baremetalhost,
            custom_api, target_namespace, bmh, server_name
        )

        # Create NMStateConfig for Dell servers
        if server_vendor:
            operator_logger.info(f"The VLAN ID is: {vlan_id}")
            if server_vendor.upper() == "DELL" and vlan_id:
                nmstate_config = yaml_generator.generate_nmstate_config(
                    name=server_name,
                    namespace=target_namespace,
                    macAddress=mac_address,
                    infra_env=infra_env,
                    vlanId=vlan_id
                )
                # Run blocking Kubernetes API call in thread pool
                await asyncio.to_thread(
                    OpenShiftUtils.create_nmstate_config,
                    custom_api, target_namespace, nmstate_config, server_name
                )

        # Update status to Completed
        patch.status["phase"] = Phase.COMPLETED
        patch.status["message"] = f"Successfully created BareMetalHost {server_name}"
        patch.status["bmhName"] = server_name
        patch.status["bmhNamespace"] = target_namespace
        patch.status["macAddress"] = mac_address
        patch.status["ipmiAddress"] = ip_address
        patch.status["serverVendor"] = server_vendor
        patch.status["vlanId"] = vlan_id

        handler_duration = time.time() - handler_start_time
        operator_logger.info(f"[CREATE] Successfully completed BareMetalHost creation for: {server_name} (took {handler_duration:.2f}s)")

    except Exception as e:
        handler_duration = time.time() - handler_start_time
        operator_logger.error(f"[CREATE] Error processing BareMetalHostGenerator {name} after {handler_duration:.2f}s: {e}", exc_info=True)

        # Update status using kopf's patch mechanism
        patch.status["phase"] = Phase.FAILED
        patch.status["message"] = str(e)

        # Preserve MAC/IP if they were retrieved before error
        if 'mac_address' in locals() and mac_address:
            patch.status["macAddress"] = mac_address
        if 'ip_address' in locals() and ip_address:
            patch.status["ipmiAddress"] = ip_address
        if 'server_vendor' in locals() and server_vendor:
            patch.status["serverVendor"] = server_vendor

        raise kopf.PermanentError(f"Failed to create BareMetalHost for {server_name}: {e}")


@kopf.on.update(BMHGenCRD.GROUP, BMHGenCRD.VERSION, BMHGenCRD.PLURAL)
async def update_bmh(spec, status, name, **kwargs):
    """Handler for updates to BareMetalHostGenerator - currently ignored as resource is immutable"""
    operator_logger.info(f"BareMetalHostGenerator {name} update ignored - resource is immutable.")
    operator_logger.debug(f"Current status: {status}")
    return status


@kopf.on.delete(BMHGenCRD.GROUP, BMHGenCRD.VERSION, BMHGenCRD.PLURAL)
async def delete_bmh(spec, name, namespace, status, **kwargs):
    """
    Handler for deleting BareMetalHostGenerator CRDs.

    This handler cleans up associated resources:
    - NMStateConfig (for Dell servers)
    - BMC Secret
    - BareMetalHost
    """
    handler_start_time = time.time()
    operator_logger.info(f"[DELETE] Starting handler for BareMetalHost Generator: {name} in namespace: {namespace}")

    if status.get('bmhName') and status.get('bmhNamespace'):
        bmh_name = status['bmhName']
        bmh_namespace = status['bmhNamespace']
        server_vendor = status.get('serverVendor')
        vlan_id = status.get('vlanId')

        try:
            # Delete NMStateConfig if exists (Dell servers only)
            if server_vendor and server_vendor.upper() == 'DELL':
                nmstate_config_name = bmh_name
                # Run blocking Kubernetes API call in thread pool
                await asyncio.to_thread(
                    OpenShiftUtils.delete_nmstate_config,
                    custom_api, bmh_namespace, nmstate_config_name
                )
                operator_logger.info(
                    f"Deleted NMStateConfig: {nmstate_config_name} in namespace: {bmh_namespace}"
                )

            # Delete BMC Secret
            bmc_secret_name = f"{server_vendor.lower()}-cred-{bmh_name}" if server_vendor else f"bmc-cred-{bmh_name}"
            # Run blocking Kubernetes API call in thread pool
            await asyncio.to_thread(
                OpenShiftUtils.delete_bmc_secret,
                core_api, bmh_namespace, bmc_secret_name
            )
            operator_logger.info(
                f"Deleted BMC Secret: {bmc_secret_name} in namespace: {bmh_namespace}"
            )

            # Delete BareMetalHost
            # Run blocking Kubernetes API call in thread pool
            await asyncio.to_thread(
                OpenShiftUtils.delete_baremetalhost,
                custom_api, bmh_namespace, bmh_name
            )
            operator_logger.info(
                f"Deleted BareMetalHost: {bmh_name} in namespace: {bmh_namespace}"
            )

            handler_duration = time.time() - handler_start_time
            operator_logger.info(f"[DELETE] Successfully completed deletion for: {name} (took {handler_duration:.2f}s)")

        except Exception as e:
            handler_duration = time.time() - handler_start_time
            operator_logger.error(f"[DELETE] Error deleting BareMetalHost and related resources for {name} after {handler_duration:.2f}s: {str(e)}", exc_info=True)
            raise kopf.PermanentError(f"Error deleting BareMetalHost and related resources: {str(e)}")
    else:
        handler_duration = time.time() - handler_start_time
        operator_logger.warning(f"[DELETE] No associated BareMetalHost found for generator: {name} (took {handler_duration:.2f}s)")


@kopf.on.cleanup()
async def cleanup_fn(**kwargs):
    """
    Cleanup function called on operator shutdown.

    This handler:
    - Cancels background buffer check task
    - Requests shutdown of buffer manager
    - Disconnects from server management systems
    """
    operator_logger.info("Operator shutting down, cleaning up resources")

    # Cancel background buffer check task
    global _buffer_check_task
    if _buffer_check_task and not _buffer_check_task.done():
        operator_logger.info("Cancelling buffer check task...")
        _buffer_check_task.cancel()
        try:
            await _buffer_check_task
        except asyncio.CancelledError:
            operator_logger.info("Buffer check task cancelled successfully")

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
