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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# BMH Generator Functions (from bmh_generator.py)
# ============================================================================

def validate_inputs(mac: str, ip: str) -> None:
    if not mac or not ip:
        raise ValueError("MAC address and IP address must not be empty")
    
    _MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
    
    if not _MAC_RE.fullmatch(mac):
        raise ValueError(f"Invalid MAC address format: {mac}")
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {ip}") from exc


def validate_yaml_format(data: Dict[str, Any]) -> None:
    """Validate that the generated data can be properly serialized to YAML format"""
    try:
        yaml.dump(data, default_flow_style=False)
    except yaml.YAMLError as exc:
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
    
    validate_yaml_format(bmh_data)
    return bmh_data


def generate_bmc_secret(
    name: str,
    namespace: str,
    username: str,
    password: str,
) -> Dict[str, Any]:
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
        
    def connect(self):
        if not all([self.ucs_ip, self.username, self.password]):
            raise ValueError("UCS IP, username, and password must be provided")
            
        self.handle = UcsHandle(self.ucs_ip, self.username, self.password)
        self.handle.login()
        
    def get_all_servers(self):
        if not self.handle:
            raise RuntimeError("Not connected to UCS. Call connect() first.")
            
        servers = self.handle.query_classid("computeRackUnit")
        return servers

    def get_server_info(self, server_name):
        """Get server MAC and IPMI address by server name"""
        if not self.handle:
            self.connect()
            
        servers = self.get_all_servers()
        mac_address, kvm_ip = self.get_ucs_info_for_node(server_name, servers)
        
        if not mac_address or not kvm_ip:
            raise ValueError(f"Could not find server {server_name} or retrieve its information")
            
        return mac_address, kvm_ip

    def get_ucs_info_for_node(self, node, servers):
        print(f"Processing node: {node}")

        for server in servers:
            domain = server.dn.split("/")[0]
            rack_id = server.pn_dn.split("-")[-1] if hasattr(server, 'pn_dn') else ""             
            
            if node in server.name:
                ucsm_handle = UcsHandle(domain, self.username, self.password)
                ucsm_handle.login()
                try: 
                    server_details = ucsm_handle.query_dn(server.dn)
                    
                    kvm_ip = self._get_kvm_ip(ucsm_handle, server_details)
                    mac_address = self._get_mac_address(ucsm_handle, server_details)
                    
                    ucsm_handle.logout()
                    return mac_address, kvm_ip
                except Exception as e:
                    print(f"Error retrieving data for {node}: {str(e)}")
                finally:
                    ucsm_handle.logout()

    def _get_kvm_ip(self, ucsm_handle, server_details):
        mgmt_interfaces = ucsm_handle.query_children(in_mo=server_details, class_id="mgmtInterface")
        print(f"Management interfaces: {mgmt_interfaces}")
        
        kvm_ip = ""
        for iface in mgmt_interfaces:
            if hasattr(iface, 'ip_address') and iface.ip_address:
                kvm_ip = iface.ip_address
                break
        return kvm_ip

    def _get_mac_address(self, ucsm_handle, server_details):
        adapters = ucsm_handle.query_children(in_mo=server_details, class_id="adaptorUnit")
        
        mac_address = ""
        if adapters:
            vnics = ucsm_handle.query_children(in_mo=adapters[0], class_id="adaptorHostEthIf")
            print(f"vNICs: {vnics}")
            if vnics and hasattr(vnics[0], 'mac'):
                mac_address = vnics[0].mac
        return mac_address


# ============================================================================
# Kubernetes Operator (from operator.py)
# ============================================================================

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


# ============================================================================
# Main entry point
# ============================================================================

if __name__ == "__main__":
    # When running as a Kubernetes operator
    kopf.run()