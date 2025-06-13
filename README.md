# BareMetalHost Generator Operator

A Kubernetes operator that automatically creates BareMetalHost resources by querying multiple server management systems (HP OneView, Cisco UCS Central, and Dell OpenManage Enterprise). This operator simplifies the process of onboarding bare metal servers from different vendors into Metal3 and OpenShift bare metal deployments.

## Overview

The BareMetalHostGenerator operator:
- Connects to multiple server management systems:
  - **HP OneView** for HP ProLiant servers
  - **Cisco UCS Central** for Cisco UCS servers
  - **Dell OpenManage Enterprise (OME)** for Dell PowerEdge servers
- Automatically detects server vendor based on annotations or naming conventions
- Queries the appropriate management system for server information (MAC addresses and management IPs)
- Creates BareMetalHost resources with vendor-specific BMC configurations
- Generates BMC secrets for IPMI/Redfish/iDRAC authentication
- Implements a buffering mechanism to limit the number of available servers
- Integrates with OpenShift Agent-based Installation workflows

## Key Features

- **Multi-vendor support**: Handles HP, Cisco, and Dell servers with appropriate BMC protocols
- **Automatic vendor detection**: Uses explicit annotations or server naming patterns
- **Buffer management**: Limits available BareMetalHosts to prevent resource exhaustion
- **Vendor-specific BMC protocols**:
  - HP: Redfish virtual media
  - Dell: iDRAC virtual media  
  - Cisco: IPMI
- **Flexible credential management**: Separate credentials for each vendor's management system
- **Status tracking**: Detailed status updates including Processing, Buffered, Completed, and Failed states

## Architecture

The operator consists of:
- **Custom Resource Definition (CRD)**: `BareMetalHostGenerator` - defines the desired server configuration
- **Controller**: Watches for CRD creation and handles server lookup, buffering, and BMH creation
- **UnifiedServerClient**: Interfaces with multiple vendor management systems
- **Buffer Manager**: Controls the number of available BareMetalHosts in the cluster

## Prerequisites

- Kubernetes cluster with Metal3 installed
- One or more of the following management systems:
  - HP OneView with API access
  - Cisco UCS Central with registered UCS Managers
  - Dell OpenManage Enterprise (OME) with managed servers
- Appropriate RBAC permissions for the operator
- Python 3.9+ environment (for development)

## Installation

### 1. Deploy the CRD

```bash
kubectl apply -f deploy/crd.yaml
```

### 2. Create Namespace and RBAC

```bash
# Create the metal3-system namespace if it doesn't exist
kubectl create namespace metal3-system

# Apply RBAC configuration
kubectl apply -f deploy/rbac.yaml
```

### 3. Configure Management System Credentials

The operator needs credentials for each management system you plan to use. You don't need to configure all systems - only the ones you have.

#### HP OneView Configuration

```yaml
# HP OneView credentials
apiVersion: v1
kind: Secret
metadata:
  name: hp-oneview-credentials
  namespace: metal3-system
type: Opaque
stringData:
  username: "your-oneview-username"
  password: "your-oneview-password"
---
# HP iLO credentials (for BMC access)
apiVersion: v1
kind: Secret
metadata:
  name: hp-ilo-credentials
  namespace: metal3-system
type: Opaque
stringData:
  username: "your-ilo-username"
  password: "your-ilo-password"
```

#### Cisco UCS Configuration

```yaml
# UCS Central credentials
apiVersion: v1
kind: Secret
metadata:
  name: ucs-central-credentials
  namespace: metal3-system
type: Opaque
stringData:
  username: "your-ucs-central-username"
  password: "your-ucs-central-password"
---
# UCS Manager credentials (used for all UCS Managers)
apiVersion: v1
kind: Secret
metadata:
  name: ucs-manager-credentials
  namespace: metal3-system
type: Opaque
stringData:
  username: "your-ucs-manager-username"
  password: "your-ucs-manager-password"
```

#### Dell OME Configuration

```yaml
# Dell OME credentials
apiVersion: v1
kind: Secret
metadata:
  name: dell-ome-credentials
  namespace: metal3-system
type: Opaque
stringData:
  username: "your-ome-username"
  password: "your-ome-password"
---
# Dell iDRAC credentials (for BMC access)
apiVersion: v1
kind: Secret
metadata:
  name: dell-idrac-credentials
  namespace: metal3-system
type: Opaque
stringData:
  username: "your-idrac-username"
  password: "your-idrac-password"
```

### 4. Configure Management System IPs

Update the ConfigMap with your management system IP addresses:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bmh-generator-config
  namespace: metal3-system
data:
  # Only configure the systems you have
  HP_ONEVIEW_IP: "10.0.0.1"    # HP OneView IP (optional)
  UCS_CENTRAL_IP: "10.0.0.2"   # Cisco UCS Central IP (optional)
  DELL_OME_IP: "10.0.0.3"      # Dell OME IP (optional)
```

### 5. Deploy the Operator

```bash
kubectl apply -f deploy/deployment.yaml
```

### 6. Verify Installation

```bash
# Check if the operator is running
kubectl get pods -n metal3-system -l app=bmh-generator-operator

# Check operator logs
kubectl logs -n metal3-system -l app=bmh-generator-operator

# Verify which management systems are configured
kubectl logs -n metal3-system -l app=bmh-generator-operator | grep "Configured server management systems"
```

## Usage

### Creating a BareMetalHostGenerator

Create a YAML file with your server configuration:

```yaml
apiVersion: infra.example.com/v1alpha1
kind: BareMetalHostGenerator
metadata:
  name: my-server-01
  namespace: openshift-machine-api
  annotations:
    server_vendor: "HP"  # HP, Dell, or Cisco
spec:
  serverName: "ESXi-Host-01"  # Name of server in management system
  namespace: "openshift-machine-api"  # Target namespace for BareMetalHost
  infraEnv: "ocp4-cluster"  # InfraEnv name for OpenShift Agent-based installation
  labels:  # Additional labels for the BareMetalHost
    node-role.kubernetes.io/worker: ""
    rack: "A1"
```

### Server Vendor Detection

The operator determines the server vendor using:

1. **Explicit annotation** (recommended):
   ```yaml
   metadata:
     annotations:
       server_vendor: "HP"  # or "Dell" or "Cisco"
   ```

2. **Naming convention** (fallback):
   - Names containing 'rf' → HP servers
   - Names containing 'ome' → Dell servers
   - All others → Cisco servers

### Apply the Configuration

```bash
# Create the BareMetalHostGenerator
kubectl apply -f my-server.yaml

# Check status
kubectl get bmhgen -n openshift-machine-api

# Get detailed information
kubectl describe bmhgen my-server-01 -n openshift-machine-api

# Check if server was buffered
kubectl get bmhgen my-server-01 -n openshift-machine-api -o jsonpath='{.status.phase}'
```

### Understanding Server Buffering

The operator implements a buffering mechanism to prevent too many servers from being available at once:

- **MAX_AVAILABLE_SERVERS**: 20 (default)
- When the limit is reached, new servers are put in "Buffered" state
- Buffered servers are automatically released when space becomes available
- Buffer check runs every 30 seconds

Status phases:
- **Processing**: Operator is querying management systems
- **Buffered**: Server information retrieved but waiting for available slot
- **Completed**: BareMetalHost successfully created
- **Failed**: Error occurred during processing

### Monitoring Buffered Servers

```bash
# View all buffered servers
kubectl get bmhgen --all-namespaces -o json | jq '.items[] | select(.status.phase=="Buffered") | {name: .metadata.name, namespace: .metadata.namespace, bufferedAt: .status.bufferedAt}'

# Check available BareMetalHost count
kubectl get bmh --all-namespaces -o json | jq '[.items[] | select(.status.provisioning.state != "provisioned")] | length'

# Watch operator buffer management logs
kubectl logs -n metal3-system -l app=bmh-generator-operator | grep -i buffer
```

## Configuration Options

### BareMetalHostGenerator Spec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `serverName` | string | No | Name of the server in management system (defaults to CR name) |
| `namespace` | string | No | Target namespace for BareMetalHost (defaults to current namespace) |
| `infraEnv` | string | Yes | InfraEnv name for OpenShift Agent-based installation |
| `labels` | map | No | Additional labels to add to BareMetalHost |

### BareMetalHostGenerator Annotations

| Annotation | Values | Description |
|------------|--------|-------------|
| `server_vendor` | HP, Dell, Cisco | Explicitly specify server vendor |

### Environment Variables

The operator uses the following environment variables:

| Variable | Description | Required | Used For |
|----------|-------------|----------|----------|
| `HP_ONEVIEW_IP` | HP OneView IP address | No* | HP servers |
| `HP_ONEVIEW_USERNAME` | HP OneView username | No* | HP servers |
| `HP_ONEVIEW_PASSWORD` | HP OneView password | No* | HP servers |
| `UCS_CENTRAL_IP` | UCS Central IP address | No* | Cisco servers |
| `UCS_CENTRAL_USERNAME` | UCS Central username | No* | Cisco servers |
| `UCS_CENTRAL_PASSWORD` | UCS Central password | No* | Cisco servers |
| `UCS_MANAGER_USERNAME` | UCS Manager username | No* | Cisco servers |
| `UCS_MANAGER_PASSWORD` | UCS Manager password | No* | Cisco servers |
| `DELL_OME_IP` | Dell OME IP address | No* | Dell servers |
| `DELL_OME_USERNAME` | Dell OME username | No* | Dell servers |
| `DELL_OME_PASSWORD` | Dell OME password | No* | Dell servers |
| `IPMI_USERNAME` | Default IPMI/BMC username | Yes | All vendors |
| `IPMI_PASSWORD` | Default IPMI/BMC password | Yes | All vendors |

*At least one vendor's configuration must be provided

## Generated Resources

For each BareMetalHostGenerator, the operator creates:

1. **BareMetalHost**: The main Metal3 resource with vendor-specific BMC configuration
2. **Secret**: BMC credentials for server access (named based on vendor)

### Vendor-Specific BMC Configurations

#### HP Servers
```yaml
spec:
  bmc:
    address: "redfish-virtualmedia://10.0.0.100/redfish/v1/Systems/1"
    credentialsName: "hp-bmc-servername"
```

#### Dell Servers
```yaml
spec:
  bmc:
    address: "idrac-virtualmedia://10.0.0.101/redfish/v1/Systems/System.Embedded.1"
    credentialsName: "dell-bmc-servername"
```

#### Cisco Servers
```yaml
spec:
  bmc:
    address: "ipmi://10.0.0.102"
    credentialsName: "cisco-bmc-servername"
```

## Troubleshooting

### Common Issues

1. **Management System Connection Errors**
   ```bash
   # Check operator logs for connection issues
   kubectl logs -n metal3-system -l app=bmh-generator-operator | grep -E "Error|Failed|Warning"
   
   # Verify credentials are properly set
   kubectl get secrets -n metal3-system
   ```

2. **Server Not Found**
   ```bash
   # Check if server name exists in management system
   kubectl describe bmhgen <name> -n <namespace>
   
   # View detailed search logs
   kubectl logs -n metal3-system -l app=bmh-generator-operator | grep -i "Searching"
   ```

3. **Server Buffered Instead of Created**
   ```bash
   # Check current available count
   kubectl get bmh --all-namespaces -o json | jq '[.items[] | select(.status.provisioning.state != "provisioned")] | length'
   
   # View buffer status
   kubectl logs -n metal3-system -l app=bmh-generator-operator | grep "Current available BareMetalHosts"
   ```

4. **Wrong Vendor Detection**
   ```bash
   # Add explicit vendor annotation
   kubectl annotate bmhgen <name> -n <namespace> server_vendor=HP --overwrite
   ```

### Debug Commands

```bash
# Get all BareMetalHostGenerators with their status
kubectl get bmhgen --all-namespaces -o custom-columns=NAME:.metadata.name,NAMESPACE:.metadata.namespace,VENDOR:.metadata.annotations.server_vendor,PHASE:.status.phase,MESSAGE:.status.message

# Check which management systems are available
kubectl logs -n metal3-system deployment/bmh-generator-operator | head -50 | grep "Configured"

# Monitor buffer management in real-time
kubectl logs -n metal3-system deployment/bmh-generator-operator -f | grep -i buffer

# View failed generators
kubectl get bmhgen --all-namespaces -o json | jq '.items[] | select(.status.phase=="Failed") | {name: .metadata.name, error: .status.message}'
```

## Development

### Local Development

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set environment variables for your available systems:
   ```bash
   # HP OneView (if available)
   export HP_ONEVIEW_IP="10.0.0.1"
   export HP_ONEVIEW_USERNAME="administrator"
   export HP_ONEVIEW_PASSWORD="your-password"
   
   # Cisco UCS (if available)
   export UCS_CENTRAL_IP="10.0.0.2"
   export UCS_CENTRAL_USERNAME="admin"
   export UCS_CENTRAL_PASSWORD="your-password"
   export UCS_MANAGER_USERNAME="admin"
   export UCS_MANAGER_PASSWORD="your-password"
   
   # Dell OME (if available)
   export DELL_OME_IP="10.0.0.3"
   export DELL_OME_USERNAME="admin"
   export DELL_OME_PASSWORD="your-password"
   
   # IPMI credentials (required)
   export IPMI_USERNAME="admin"
   export IPMI_PASSWORD="password"
   ```

3. Run locally:
   ```bash
   kopf run --liveness=http://0.0.0.0:8080/healthz src/operator_bmh_gen.py --all-namespaces
   ```

### Testing Unified Server Client

```python
from src.operator_bmh_gen import UnifiedServerClient

# Initialize client with available systems
client = UnifiedServerClient(
    oneview_ip='10.0.0.1',
    oneview_username='admin',
    oneview_password='password',
    # Add other systems as needed
)

# Test server lookup with explicit vendor
mac, ip = client.get_server_info('MyServer', server_vendor='HP')
print(f"Found: MAC={mac}, IP={ip}")

# Test auto-detection
mac, ip = client.get_server_info('rf-compute-01')  # Auto-detects as HP
print(f"Found: MAC={mac}, IP={ip}")
```

### Building the Container

```bash
# Build the container
docker build -t your-registry/bmh-generator-operator:latest .

# Push to registry
docker push your-registry/bmh-generator-operator:latest
```

## Buffer Management Details

The operator implements sophisticated buffer management:

1. **Limit Enforcement**: Maximum 20 BareMetalHosts can be "available" (not provisioned)
2. **Automatic Buffering**: When limit is reached, new servers are buffered with their discovered information
3. **FIFO Release**: Buffered servers are released in order (first buffered, first released)
4. **Periodic Checks**: Every 30 seconds, the operator checks if slots are available
5. **Status Preservation**: Buffered servers maintain their discovered MAC and IP information

## Security Considerations

- Store all credentials in Kubernetes secrets
- Use separate credentials for each vendor's management system
- Different credentials for management systems vs BMC/IPMI access
- Enable network policies to restrict operator communication
- Regularly rotate credentials
- Consider using external secret management solutions
- Ensure secure communication with all management systems

## Multi-Vendor Workflow

The operator follows this workflow:

1. **Vendor Detection**: Determines vendor from annotation or naming pattern
2. **System Selection**: Chooses primary management system based on vendor
3. **Server Search**: Queries the primary system first, then others if not found
4. **Information Extraction**: 
   - HP: Queries OneView for server hardware and iLO information
   - Cisco: Connects to UCS Central, finds domain, queries UCS Manager
   - Dell: Queries OME for device information and iDRAC details
5. **BMC Configuration**: Creates vendor-specific BMC address format
6. **Resource Creation**: Generates BareMetalHost with appropriate settings

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Support

For issues and questions:
- Check the troubleshooting section
- Review operator logs for detailed error messages
- Verify management system connectivity
- Open an issue in the project repository