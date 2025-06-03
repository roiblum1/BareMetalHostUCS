import re
import ipaddress
import base64
import yaml
import os
import logging
import subprocess
import kopf
import kubernetes
from kubernetes import client, config
from typing import Dict, Any, Optional
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

# ============================================================================
# BMH Generator Functions (from bmh_generator.py)
# ============================================================================

def validate_inputs(mac: str, ip: str) -> None:
    """Validate MAC and IP address formats"""
    bmh_logger.debug(f"Validating inputs - MAC: {mac}, IP: {ip}")
    
    if not mac or not ip:
        bmh_logger.error("MAC address and/or IP address is empty")
        raise ValueError("MAC address and IP address must not be empty")
    
    _MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
    
    if not _MAC_RE.fullmatch(mac):
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
    def __init__(self, ucs_ip=None, username=None, password=None):
        self.ucs_ip = ucs_ip
        self.username = username
        self.password = password
        self.handle = None
        ucs_logger.info(f"Initialized UCS client for endpoint: {ucs_ip}")
        
    def connect(self):
        """Connect to UCS Manager"""
        ucs_logger.info(f"Attempting to connect to UCS at {self.ucs_ip}")
        
        if not all([self.ucs_ip, self.username, self.password]):
            ucs_logger.error("Missing required UCS connection parameters")
            raise ValueError("UCS IP, username, and password must be provided")
        
        try:
            self.handle = UcsHandle(self.ucs_ip, self.username, self.password)
            self.handle.login()
            ucs_logger.info(f"Successfully connected to UCS at {self.ucs_ip}")
        except Exception as e:
            ucs_logger.error(f"Failed to connect to UCS: {str(e)}")
            raise
        
    def get_all_servers(self):
        """Query all rack servers from UCS"""
        ucs_logger.debug("Querying all compute rack units")
        
        if not self.handle:
            ucs_logger.error("Not connected to UCS")
            raise RuntimeError("Not connected to UCS. Call connect() first.")
        
        try:
            servers = self.handle.query_classid("computeRackUnit")
            ucs_logger.info(f"Found {len(servers)} servers in UCS")
            return servers
        except Exception as e:
            ucs_logger.error(f"Failed to query servers: {str(e)}")
            raise

    def get_server_info(self, server_name):
        """Get server MAC and IPMI address by server name"""
        ucs_logger.info(f"Getting server info for: {server_name}")
        
        if not self.handle:
            ucs_logger.debug("Not connected, attempting to connect")
            self.connect()
            
        servers = self.get_all_servers()
        mac_address, kvm_ip = self.get_ucs_info_for_node(server_name, servers)
        
        if not mac_address or not kvm_ip:
            ucs_logger.error(f"Could not find complete info for server {server_name}")
            raise ValueError(f"Could not find server {server_name} or retrieve its information")
        
        ucs_logger.info(f"Retrieved info for {server_name} - MAC: {mac_address}, KVM IP: {kvm_ip}")
        return mac_address, kvm_ip

    def get_ucs_info_for_node(self, node, servers):
        """Extract UCS information for a specific node"""
        ucs_logger.info(f"Processing node: {node}")

        for server in servers:
            domain = server.dn.split("/")[0]
            rack_id = server.pn_dn.split("-")[-1] if hasattr(server, 'pn_dn') else ""
            
            ucs_logger.debug(f"Checking server: {server.name} (DN: {server.dn})")
            
            if node in server.name:
                ucs_logger.info(f"Found matching server: {server.name}")
                ucsm_handle = None
                
                try:
                    ucs_logger.debug(f"Connecting to domain: {domain}")
                    ucsm_handle = UcsHandle(domain, self.username, self.password)
                    ucsm_handle.login()
                    
                    server_details = ucsm_handle.query_dn(server.dn)
                    ucs_logger.debug(f"Retrieved server details for DN: {server.dn}")
                    
                    kvm_ip = self._get_kvm_ip(ucsm_handle, server_details)
                    mac_address = self._get_mac_address(ucsm_handle, server_details)
                    
                    ucs_logger.info(f"Successfully retrieved info - MAC: {mac_address}, KVM IP: {kvm_ip}")
                    return mac_address, kvm_ip
                    
                except Exception as e:
                    ucs_logger.error(f"Error retrieving data for {node}: {str(e)}")
                    ucs_logger.exception("Full exception details:")
                    
                finally:
                    if ucsm_handle:
                        try:
                            ucsm_handle.logout()
                            ucs_logger.debug(f"Logged out from domain: {domain}")
                        except Exception as e:
                            ucs_logger.warning(f"Failed to logout from domain {domain}: {str(e)}")
        
        ucs_logger.warning(f"No matching server found for node: {node}")
        return None, None

    def _get_kvm_ip(self, ucsm_handle, server_details):
        """Extract KVM IP address from server management interfaces"""
        ucs_logger.debug("Querying management interfaces")
        
        try:
            mgmt_interfaces = ucsm_handle.query_children(in_mo=server_details, class_id="mgmtInterface")
            ucs_logger.debug(f"Found {len(mgmt_interfaces)} management interfaces")
            
            kvm_ip = ""
            for idx, iface in enumerate(mgmt_interfaces):
                ucs_logger.debug(f"Checking interface {idx}: {iface}")
                if hasattr(iface, 'ip_address') and iface.ip_address:
                    kvm_ip = iface.ip_address
                    ucs_logger.info(f"Found KVM IP: {kvm_ip}")
                    break
            
            if not kvm_ip:
                ucs_logger.warning("No KVM IP found in management interfaces")
                
            return kvm_ip
            
        except Exception as e:
            ucs_logger.error(f"Error retrieving KVM IP: {str(e)}")
            return ""

    def _get_mac_address(self, ucsm_handle, server_details):
        """Extract MAC address from server network adapters"""
        ucs_logger.debug("Querying network adapters")
        
        try:
            adapters = ucsm_handle.query_children(in_mo=server_details, class_id="adaptorUnit")
            ucs_logger.debug(f"Found {len(adapters)} adapters")
            
            mac_address = ""
            if adapters:
                vnics = ucsm_handle.query_children(in_mo=adapters[0], class_id="adaptorHostEthIf")
                ucs_logger.debug(f"Found {len(vnics)} vNICs on first adapter")
                
                if vnics and hasattr(vnics[0], 'mac'):
                    mac_address = vnics[0].mac
                    ucs_logger.info(f"Found MAC address: {mac_address}")
                else:
                    ucs_logger.warning("No vNICs with MAC address found")
            else:
                ucs_logger.warning("No network adapters found")
                
            return mac_address
            
        except Exception as e:
            ucs_logger.error(f"Error retrieving MAC address: {str(e)}")
            return ""


# ============================================================================
# Kubernetes Operator (from operator.py)
# ============================================================================

# Load Kubernetes config
try:
    config.load_incluster_config()  # Use this when running in cluster
    operator_logger.info("Loaded in-cluster Kubernetes configuration")
except Exception as e:
    operator_logger.warning(f"Failed to load in-cluster config: {e}")
    operator_logger.info("Falling back to kubeconfig")
    config.load_kube_config()  # Use this when running locally

# Initialize Kubernetes clients
k8s_client = client.ApiClient()
custom_api = client.CustomObjectsApi(k8s_client)
core_v1 = client.CoreV1Api(k8s_client)
operator_logger.info("Initialized Kubernetes API clients")

# UCS client (initialized on startup)
ucs_client = None


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    """Configure operator settings"""
    operator_logger.info("Starting operator configuration")
    
    settings.persistence.finalizer = 'bmhgenerator.infra.example.com/finalizer'
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage()
    operator_logger.debug("Configured operator persistence settings")
    
    # Initialize UCS client
    global ucs_client
    ucs_endpoint = os.getenv('UCS_ENDPOINT', 'https://ucs.example.com')
    ucs_username = os.getenv('UCS_USERNAME', 'admin')
    ucs_password = os.getenv('UCS_PASSWORD', 'password')
    
    operator_logger.info(f"Initializing UCS client with endpoint: {ucs_endpoint}")
    operator_logger.debug(f"UCS username: {ucs_username}")
    
    ucs_client = UCSClient(ucs_endpoint, ucs_username, ucs_password)
    operator_logger.info("Operator configuration completed successfully")


@kopf.on.create('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def create_bmh(spec: Dict[str, Any], name: str, namespace: str, status: Dict[str, Any], **kwargs):
    """Handle BareMetalHostGenerator creation"""
    
    operator_logger.info(f"Processing BareMetalHostGenerator: {name} in namespace: {namespace}")
    operator_logger.debug(f"Spec: {spec}")
    
    # Extract spec fields
    server_name = spec.get('serverName', name)
    target_namespace = spec.get('namespace', namespace)
    infra_env = spec.get('infraEnv')
    
    operator_logger.info(f"Server name: {server_name}, Target namespace: {target_namespace}, InfraEnv: {infra_env}")
    
    # Optional: credentials from spec or use defaults
    ipmi_username = spec.get('ipmiUsername', os.getenv('DEFAULT_IPMI_USERNAME', 'admin'))
    ipmi_password_ref = spec.get('ipmiPasswordSecret', {})
    
    operator_logger.debug(f"IPMI username: {ipmi_username}")
    if ipmi_password_ref:
        operator_logger.debug(f"IPMI password will be read from secret: {ipmi_password_ref}")
    
    try:
        # Update status to show we're processing
        status['phase'] = 'Processing'
        status['message'] = f'Looking up server {server_name} in UCS'
        operator_logger.info(f"Status updated to Processing for {name}")
        
        # Get server info from UCS
        operator_logger.info(f"Querying UCS for server: {server_name}")
        mac_address, ipmi_address = ucs_client.get_server_info(server_name)
        operator_logger.info(f"UCS query successful - MAC: {mac_address}, IPMI: {ipmi_address}")
        
        # Get IPMI password (from secret or default)
        ipmi_password = os.getenv('DEFAULT_IPMI_PASSWORD', 'password')
        if ipmi_password_ref:
            secret_name = ipmi_password_ref.get('name')
            secret_key = ipmi_password_ref.get('key', 'password')
            operator_logger.debug(f"Reading IPMI password from secret: {secret_name}, key: {secret_key}")
            
            try:
                secret = core_v1.read_namespaced_secret(secret_name, namespace)
                ipmi_password = base64.b64decode(secret.data[secret_key]).decode()
                operator_logger.info(f"Successfully read IPMI password from secret: {secret_name}")
            except Exception as e:
                operator_logger.warning(f"Could not read IPMI password from secret: {e}")
                operator_logger.info("Using default IPMI password")
        
        # Create BMC Secret first
        operator_logger.info(f"Creating BMC secret for {server_name}")
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
            operator_logger.info(f"Successfully created BMC secret: {server_name}-bmc-secret")
        except kubernetes.client.exceptions.ApiException as e:
            if e.status == 409:  # Already exists
                operator_logger.info(f"BMC secret already exists: {server_name}-bmc-secret")
            else:
                operator_logger.error(f"Failed to create BMC secret: {e}")
                raise
        
        # Generate BareMetalHost
        operator_logger.info(f"Generating BareMetalHost for {server_name}")
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
        operator_logger.info(f"Creating BareMetalHost: {server_name} in namespace: {target_namespace}")
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
        
        operator_logger.info(f"Successfully created BareMetalHost: {server_name}")
        operator_logger.debug(f"Final status: {status}")
        
        # Return success
        return {'bmhCreated': True}
        
    except Exception as e:
        operator_logger.error(f"Failed to create BareMetalHost: {str(e)}")
        operator_logger.exception("Full exception details:")
        
        status['phase'] = 'Failed'
        status['message'] = f'Error: {str(e)}'
        raise kopf.PermanentError(f"Failed to create BareMetalHost: {str(e)}")


# Since you want it immutable, we won't react to updates
@kopf.on.update('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def update_bmh(spec, status, name, **kwargs):
    """Ignore updates - BareMetalHostGenerators are immutable"""
    operator_logger.info(f"BareMetalHostGenerator {name} update ignored - resource is immutable")
    operator_logger.debug(f"Current status: {status}")
    return status


# Optional: Add a delete handler if you want to clean up BMH when generator is deleted
@kopf.on.delete('infra.example.com', 'v1alpha1', 'baremetalhostgenerators')
async def delete_bmh(spec, name, namespace, status, **kwargs):
    """Optionally clean up BareMetalHost when generator is deleted"""
    operator_logger.info(f"Processing deletion of BareMetalHostGenerator: {name}")
    
    if status.get('bmhName') and status.get('bmhNamespace'):
        operator_logger.info(f"BareMetalHostGenerator deleted, but keeping BareMetalHost: {status['bmhName']}")
        operator_logger.debug(f"BMH location - Name: {status['bmhName']}, Namespace: {status['bmhNamespace']}")
    else:
        operator_logger.warning(f"No associated BareMetalHost found for generator: {name}")
    
    # If you want to delete the BMH too, uncomment below:
    # try:
    #     operator_logger.info(f"Attempting to delete BareMetalHost: {status['bmhName']}")
    #     custom_api.delete_namespaced_custom_object(
    #         group="metal3.io",
    #         version="v1alpha1",
    #         namespace=status['bmhNamespace'],
    #         name=status['bmhName']
    #     )
    #     operator_logger.info(f"Successfully deleted BareMetalHost: {status['bmhName']}")
    # except Exception as e:
    #     operator_logger.error(f"Failed to delete BareMetalHost: {e}")
    #     pass


# ============================================================================
# Main entry point
# ============================================================================

if __name__ == "__main__":
    # When running as a Kubernetes operator
    operator_logger.info("Starting BareMetalHost Generator Operator")
    operator_logger.info(f"Process PID: {os.getpid()}")
    operator_logger.info(f"Python version: {subprocess.check_output(['python', '--version']).decode().strip()}")
    
    try:
        kopf.run()
    except Exception as e:
        operator_logger.critical(f"Operator crashed: {str(e)}")
        operator_logger.exception("Full crash details:")
        raise