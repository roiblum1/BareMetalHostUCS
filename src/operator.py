import kopf
import kubernetes
from kubernetes import client, config
import os
import logging
from typing import Dict, Any
import base64
from .ucs_client import UCSClient
from .bmh_generator import generate_baremetal_host, generate_bmc_secret

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load Kubernetes config
try:
    config.load_incluster_config()  # Use this when running in cluster
except:
    config.load_kube_config()  # Use this when running locally

# Initialize Kubernetes clients
k8s_client = client.ApiClient()
custom_api = client.CustomObjectsApi(k8s_client)
core_v1 = client.CoreV1Api(k8s_client)

# UCS client (initialized on startup)
ucs_client = None

@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    """Configure operator settings"""
    settings.persistence.finalizer = 'bmhgenerator.infra.example.com/finalizer'
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage()
    
    # Initialize UCS client
    global ucs_client
    ucs_endpoint = os.getenv('UCS_ENDPOINT', 'https://ucs.example.com')
    ucs_username = os.getenv('UCS_USERNAME', 'admin')
    ucs_password = os.getenv('UCS_PASSWORD', 'password')
    
    ucs_client = UCSClient(ucs_endpoint, ucs_username, ucs_password)
    logger.info(f"Initialized UCS client for endpoint: {ucs_endpoint}")

@kopf.on.create('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def create_bmh(spec: Dict[str, Any], name: str, namespace: str, status: Dict[str, Any], **kwargs):
    """Handle BareMetalHostGenerator creation"""
    
    logger.info(f"Processing BareMetalHostGenerator: {name}")
    
    # Extract spec fields
    server_name = spec.get('serverName', name)
    target_namespace = spec.get('namespace', namespace)
    infra_env = spec.get('infraEnv')
    
    # Optional: credentials from spec or use defaults
    ipmi_username = spec.get('ipmiUsername', os.getenv('DEFAULT_IPMI_USERNAME', 'admin'))
    ipmi_password_ref = spec.get('ipmiPasswordSecret', {})
    
    try:
        # Update status to show we're processing
        status['phase'] = 'Processing'
        status['message'] = f'Looking up server {server_name} in UCS'
        
        # Get server info from UCS
        logger.info(f"Querying UCS for server: {server_name}")
        mac_address, ipmi_address = ucs_client.get_server_info(server_name)
        logger.info(f"Found server - MAC: {mac_address}, IPMI: {ipmi_address}")
        
        # Get IPMI password (from secret or default)
        ipmi_password = os.getenv('DEFAULT_IPMI_PASSWORD', 'password')
        if ipmi_password_ref:
            secret_name = ipmi_password_ref.get('name')
            secret_key = ipmi_password_ref.get('key', 'password')
            try:
                secret = core_v1.read_namespaced_secret(secret_name, namespace)
                ipmi_password = base64.b64decode(secret.data[secret_key]).decode()
            except Exception as e:
                logger.warning(f"Could not read IPMI password from secret: {e}")
        
        # Create BMC Secret first
        logger.info(f"Creating BMC secret for {server_name}")
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
            logger.info(f"Created BMC secret: {server_name}-bmc-secret")
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 409:  # Already exists
                logger.info(f"BMC secret already exists: {server_name}-bmc-secret")
            else:
                raise
        
        # Generate BareMetalHost
        logger.info(f"Generating BareMetalHost for {server_name}")
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
        
        # Create BareMetalHost
        logger.info(f"Creating BareMetalHost: {server_name}")
        custom_api.create_namespaced_custom_object(
            group="metal3.io",
            version="v1alpha1",
            namespace=target_namespace,
            plural="baremetalhosts",
            body=bmh
        )
        
        # Update status to success
        status['phase'] = 'Completed'
        status['message'] = f'Successfully created BareMetalHost {server_name}'
        status['bmhName'] = server_name
        status['bmhNamespace'] = target_namespace
        
        logger.info(f"Successfully created BareMetalHost: {server_name}")
        
        # Return success
        return {'bmhCreated': True}
        
    except Exception as e:
        logger.error(f"Failed to create BareMetalHost: {str(e)}")
        status['phase'] = 'Failed'
        status['message'] = f'Error: {str(e)}'
        raise kopf.PermanentError(f"Failed to create BareMetalHost: {str(e)}")

# Since you want it immutable, we won't react to updates
@kopf.on.update('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def update_bmh(spec, status, **kwargs):
    """Ignore updates - BareMetalHostGenerators are immutable"""
    logger.info("BareMetalHostGenerator update ignored - resource is immutable")
    return status

# Optional: Add a delete handler if you want to clean up BMH when generator is deleted
@kopf.on.delete('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def delete_bmh(spec, name, namespace, status, **kwargs):
    """Optionally clean up BareMetalHost when generator is deleted"""
    if status.get('bmhName') and status.get('bmhNamespace'):
        logger.info(f"BareMetalHostGenerator deleted, but keeping BareMetalHost: {status['bmhName']}")
    # If you want to delete the BMH too, uncomment below:
    # try:
    #     custom_api.delete_namespaced_custom_object(
    #         group="metal3.io",
    #         version="v1alpha1",
    #         namespace=status['bmhNamespace'],
    #         name=status['bmhName']
    #     )
    # except:
    #     pass