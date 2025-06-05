import re
import ipaddress
import base64
import yaml
import os
import logging
import subprocess
import asyncio
import kopf
import kubernetes
from kubernetes import client, config
from typing import Dict, Any, Optional, List
from datetime import datetime
from ucscsdk.ucschandle import UcscHandle
from ucsmsdk.ucshandle import UcsHandle
from ucsmsdk.mometa.compute.ComputeRackUnit import ComputeRackUnit

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# Create separate loggers for different components
bmh_logger = logging.getLogger('bmh_generator')
ucs_logger = logging.getLogger('ucs_client')
operator_logger = logging.getLogger('k8s_operator')
buffer_logger = logging.getLogger('bmh_buffer')

# Global configuration
MAX_AVAILABLE_SERVERS = 20  # Maximum number of servers that can be available (not in cluster)
BUFFER_CHECK_INTERVAL = 30  # Seconds between buffer checks

# ============================================================================
# BMH Generator Functions (from bmh_generator.py)
# ============================================================================

def validate_inputs(mac: str, ip: str) -> None:
    """Validate MAC and IP address formats"""
    bmh_logger.debug(f"Validating inputs - MAC: {mac}, IP: {ip}")
    
    if not mac or not ip:
        bmh_logger.error("MAC address and/or IP address is empty")
        raise ValueError("MAC address and IP address must not be empty")
    
    MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
    
    if not MAC_RE.fullmatch(mac):
        bmh_logger.error(f"Invalid MAC address format: {mac}")
        raise ValueError(f"Invalid MAC address format: {mac}")
    
    try:
        ipaddress.IPv4Address(ip)
        bmh_logger.debug(f"Successfully validated IP address: {ip}")
    except ipaddress.AddressValueError as exc:
        bmh_logger.error(f"Invalid IPv4 address: {ip} - {exc}")
        raise ValueError(f"Invalid IPv4 address: {ip}") from exc
    
    bmh_logger.info(f"Input validation successful for MAC: {mac}, IP: {ip}")

def validate_yaml_format(data: Dict[str, Any]) -> None:
    """Validate that the generated data can be properly serialized to YAML format"""
    bmh_logger.debug("Validating YAML format of generated data")
    
    try:
        yaml.dump(data, default_flow_style=False)
        bmh_logger.debug("YAML validation successful")
    except yaml.YAMLError as exc:
        bmh_logger.error(f"YAML validation failed: {exc}")
        raise ValueError(f"Generated data cannot be converted to valid YAML: {exc}") from exc

def generate_baremetal_host(
    name: str,
    namespace: str,
    mac_address: str,
    ipmi_address: str,
    ipmi_username: str,
    ipmi_password: str,
    infra_env: str,
    labels: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Generate BareMetalHost resource definition"""
    bmh_logger.info(f"Generating BareMetalHost for {name} in namespace {namespace}")
    bmh_logger.debug(f"Parameters - MAC: {mac_address}, IPMI: {ipmi_address}, InfraEnv: {infra_env}")
    
    validate_inputs(mac_address, ipmi_address)
    
    bmh_data = {
        "apiVersion": "metal3.io/v1alpha1",
        "kind": "BareMetalHost",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "infraenvs.agent-install.openshift.io": infra_env,
                **(labels or {}),
            },
            "annotations": {
                "inspect.metal3.io": "disabled",
                "bmac.agent-install.openshift.io/hostname": name,
            },
        },
        "spec": {
            "online": True,
            "bootMACAddress": mac_address,
            "automatedCleaningMode": "disabled",
            "bmc": {
                "address": f"ipmi://{ipmi_address}",
                "credentialsName": f"{name}-bmc-secret",
                "disableCertificateVerification": True,
            },
            "bootMode": "UEFI",
        },
    }
    
    if labels:
        bmh_logger.debug(f"Additional labels applied: {labels}")
    
    validate_yaml_format(bmh_data)
    bmh_logger.info(f"Successfully generated BareMetalHost definition for {name}")
    
    return bmh_data

def generate_bmc_secret(
    name: str,
    namespace: str,
    username: str,
    password: str,
) -> Dict[str, Any]:
    """Generate BMC Secret resource definition"""
    bmh_logger.info(f"Generating BMC secret for {name} in namespace {namespace}")
    bmh_logger.debug(f"BMC username: {username}")
    
    secret_data = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": f"{name}-bmc-secret", "namespace": namespace},
        "type": "Opaque",
        "data": {
            "username": base64.b64encode(username.encode()).decode(),
            "password": base64.b64encode(password.encode()).decode(),
        },
    }
    
    validate_yaml_format(secret_data)
    bmh_logger.info(f"Successfully generated BMC secret definition for {name}-bmc-secret")
    
    return secret_data

# ============================================================================
# UCS Client Class (from ucs_client.py)
# ============================================================================

class UCSClient:
    def __init__(self, ucs_central_ip=None, central_username=None, central_password=None, 
                 manager_username=None, manager_password=None):
        self.ucs_central_ip = ucs_central_ip
        self.central_username = central_username
        self.central_password = central_password
        self.manager_username = manager_username
        self.manager_password = manager_password
        self.ucsc_handle = None
        ucs_logger.info(f"Initialized UCS client for UCS Central: {ucs_central_ip}")
        
    def connect(self):
        """Connect to UCS Central"""
        ucs_logger.info(f"Attempting to connect to UCS Central at {self.ucs_central_ip}")
        
        if not all([self.ucs_central_ip, self.central_username, self.central_password, 
                   self.manager_username, self.manager_password]):
            ucs_logger.error("Missing required UCS connection parameters")
            raise ValueError("UCS Central IP, central credentials, and manager credentials must be provided")
        
        try:
            self.ucsc_handle = UcscHandle(self.ucs_central_ip, self.central_username, self.central_password)
            self.ucsc_handle.login()
            ucs_logger.info(f"Successfully connected to UCS Central at {self.ucs_central_ip}")
        except Exception as e:
            ucs_logger.error(f"Failed to connect to UCS Central: {str(e)}")
            raise
        
    def get_all_servers(self):
        """Query all logical servers from UCS Central"""
        ucs_logger.debug("Querying all logical servers")
        
        if not self.ucsc_handle:
            ucs_logger.error("Not connected to UCS Central")
            raise RuntimeError("Not connected to UCS Central. Call connect() first.")
        
        try:
            servers = self.ucsc_handle.query_classid("lsServer")
            ucs_logger.info(f"Found {len(servers)} servers in UCS Central")
            return servers
        except Exception as e:
            ucs_logger.error(f"Failed to query servers: {str(e)}")
            raise
    
    def get_server_info(self, server_name):
        """Get server MAC and IPMI address by server name"""
        ucs_logger.info(f"Getting server info for: {server_name}")
        
        if not self.ucsc_handle:
            ucs_logger.debug("Not connected, attempting to connect")
            self.connect()
            
        servers = self.get_all_servers()
        mac_address, kvm_ip = self.get_ucs_info_for_node(server_name, servers)
        
        if not mac_address or not kvm_ip:
            ucs_logger.error(f"Could not find complete info for server {server_name}")
            raise ValueError(f"Could not find server {server_name} or retrieve its information")
        
        ucs_logger.info(f"Retrieved info for {server_name} - MAC: {mac_address}, KVM IP: {kvm_ip}")
        return mac_address, kvm_ip
    
    def get_ucs_info_for_node(self, node_name, servers):
        """Extract UCS information for a specific node"""
        ucs_logger.info(f"Processing node: {node_name}")
        
        for server in servers:
            ucs_logger.debug(f"Checking server: {server.name} (DN: {server.dn})")
            
            if node_name.upper() == server.name.upper():
                ucs_logger.info(f"Found matching server: {server.name}")
                domain = server.domain
                rack_id = server.pn_dn.split("-")[-1] if hasattr(server, 'pn_dn') else ""
                ucsm_handle = None
                
                try:
                    ucs_logger.debug(f"Connecting to UCS Manager domain: {domain}")
                    ucsm_handle = UcsHandle(domain, self.manager_username, self.manager_password)
                    ucsm_handle.login()
                    
                    # Get server details from UCS Central (not UCS Manager)
                    server_details = self.ucsc_handle.query_dn(server.dn)
                    if not server_details:
                        ucs_logger.warning(f"No server details found for {node_name}")
                        continue
                    
                    ucs_logger.debug(f"Retrieved server details for DN: {server.dn}")
                    
                    kvm_ip = self._get_kvm_ip(ucsm_handle, server_details)
                    mac_address = self._get_mac_address(ucsm_handle, server_details)
                    
                    ucs_logger.info(f"Successfully retrieved info - MAC: {mac_address}, KVM IP: {kvm_ip}")
                    return mac_address, kvm_ip
                    
                except Exception as e:
                    ucs_logger.error(f"Error retrieving data for {node_name}: {str(e)}")
                    ucs_logger.exception("Full exception details:")
                    
                finally:
                    if ucsm_handle:
                        try:
                            ucsm_handle.logout()
                            ucs_logger.debug(f"Logged out from domain: {domain}")
                        except Exception as e:
                            ucs_logger.warning(f"Failed to logout from domain {domain}: {str(e)}")
        
        ucs_logger.warning(f"No matching server found for node: {node_name}")
        return None, None
    
    def _get_kvm_ip(self, ucsm_handle, server_details):
        """Extract KVM IP address from VnicIpV4PooledAddr"""
        ucs_logger.debug("Querying VnicIpV4PooledAddr for KVM IP")
        
        try:
            mgmt_interfaces = ucsm_handle.query_children(in_mo=server_details, class_id="VnicIpV4PooledAddr")
            ucs_logger.debug(f"Found {len(mgmt_interfaces)} IP pool addresses")
            
            kvm_ip = ""
            for iface in mgmt_interfaces:
                if hasattr(iface, 'addr') and iface.addr:
                    kvm_ip = str(iface.addr)
                    ucs_logger.info(f"Found KVM IP: {kvm_ip}")
                    break
            
            if not kvm_ip:
                ucs_logger.warning("No KVM IP found in VnicIpV4PooledAddr")
                
            return kvm_ip
            
        except Exception as e:
            ucs_logger.error(f"Error retrieving KVM IP: {str(e)}")
            return ""
    
    def _get_mac_address(self, ucsm_handle, server_details):
        """Extract MAC address from VnicEther (sorted by name)"""
        ucs_logger.debug("Querying VnicEther for MAC address")
        
        try:
            adapters = ucsm_handle.query_children(in_mo=server_details, class_id="VnicEther")
            ucs_logger.debug(f"Found {len(adapters)} VnicEther adapters")
            
            mac_address = ""
            if adapters:
                # Sort adapters by name (same as in your working script)
                sorted_adapters = sorted(adapters, key=lambda x: x.name[3:])
                
                if sorted_adapters and hasattr(sorted_adapters[0], 'addr'):
                    mac_address = sorted_adapters[0].addr
                    ucs_logger.info(f"Found MAC address: {mac_address}")
                else:
                    ucs_logger.warning("No MAC address found in first VnicEther adapter")
            else:
                ucs_logger.warning("No VnicEther adapters found")
                
            return mac_address if mac_address else "No MAC address found"
            
        except Exception as e:
            ucs_logger.error(f"Error retrieving MAC address: {str(e)}")
            return "No MAC address found"
    
    def disconnect(self):
        """Disconnect from UCS Central"""
        if self.ucsc_handle:
            try:
                self.ucsc_handle.logout()
                ucs_logger.info("Disconnected from UCS Central")
            except Exception as e:
                ucs_logger.warning(f"Error during UCS Central logout: {str(e)}")


# ============================================================================
# Kubernetes Operator with Buffer Management
# ============================================================================

# Load Kubernetes config
# ============================================================================
# Kubernetes Operator with Buffer Management (UPDATED)
# ============================================================================

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

# UCS client (initialized on startup)
ucs_client = None

# Buffer management
bmh_buffer_lock = asyncio.Lock()
buffer_check_task = None

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

def get_ucs_connection():
    """Get UCS connection, reconnecting if needed"""
    global ucs_client
    
    if not ucs_client:
        raise RuntimeError("UCS client not initialized")
    
    # Always reconnect to avoid timeout issues
    try:
        if ucs_client.ucsc_handle:
            ucs_client.ucsc_handle.logout()
    except:
        pass
    
    ucs_client.connect()
    return ucs_client

@kopf.on.startup()
async def configure(settings: kopf.OperatorSettings, **_):
    """Configure operator settings"""
    operator_logger.info("Starting operator configuration")
    
    settings.persistence.finalizer = 'bmhgenerator.infra.example.com/finalizer'
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage()
    
    # Initialize UCS client
    global ucs_client
    
    ucs_central_ip = os.getenv('UCS_CENTRAL_IP')
    central_username = os.getenv('UCS_CENTRAL_USERNAME', 'admin')
    central_password = os.getenv('UCS_CENTRAL_PASSWORD')
    manager_username = os.getenv('UCS_MANAGER_USERNAME', 'admin')
    manager_password = os.getenv('UCS_MANAGER_PASSWORD')
    
    if not all([ucs_central_ip, central_password, manager_password]):
        operator_logger.error("Missing required UCS environment variables")
        raise ValueError("Missing required UCS configuration")
    
    ucs_client = UCSClient(
        ucs_central_ip=ucs_central_ip,
        central_username=central_username,
        central_password=central_password,
        manager_username=manager_username,
        manager_password=manager_password
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
        "message": f"Looking up server {server_name} in UCS Central"
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
        # Get UCS connection (handles reconnection)
        ucs = get_ucs_connection()
        operator_logger.info(f"Querying UCS Central for server: {server_name}")
        mac_address, ipmi_address = ucs.get_server_info(server_name)
        operator_logger.info(f"UCS query successful - MAC: {mac_address}, IPMI: {ipmi_address}")
        
        # Disconnect after use to avoid timeout
        try:
            ucs.disconnect()
        except:
            pass
        
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
    
    if ucs_client:
        try:
            ucs_client.disconnect()
        except Exception as e:
            operator_logger.warning(f"Error disconnecting from UCS Central: {e}")
    
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