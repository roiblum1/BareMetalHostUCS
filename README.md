# BareMetalHost Generator Operator

A Kubernetes operator that automatically creates BareMetalHost resources by querying Cisco UCS Central for server information. This operator simplifies the process of onboarding bare metal servers into Metal3 and OpenShift bare metal deployments.

## Overview

The BareMetalHostGenerator operator:
- Connects to Cisco UCS Central to discover servers across multiple UCS domains
- Queries individual UCS Managers for detailed server information (MAC addresses and IPMI/KVM IPs)
- Automatically creates BareMetalHost resources with the retrieved data
- Generates BMC secrets for IPMI authentication
- Integrates with OpenShift Agent-based Installation workflows

## Architecture

The operator consists of:
- **Custom Resource Definition (CRD)**: `BareMetalHostGenerator` - defines the desired server configuration
- **Controller**: Watches for CRD creation and handles the server lookup and BMH creation
- **UCS Client**: Interfaces with Cisco UCS Central and UCS Managers to retrieve server information

## Prerequisites

- Kubernetes cluster with Metal3 installed
- Cisco UCS Central with API access
- Cisco UCS Managers registered to UCS Central
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

### 3. Configure UCS Credentials

Create a secret for UCS Central credentials:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ucs-central-credentials
  namespace: metal3-system
type: Opaque
stringData:
  central-username: "your-ucs-central-username"
  central-password: "your-ucs-central-password"
```

Create a secret for UCS Manager credentials (used for all UCS Managers):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ucs-manager-credentials
  namespace: metal3-system
type: Opaque
stringData:
  manager-username: "your-ucs-manager-username"
  manager-password: "your-ucs-manager-password"
```

Update the ConfigMap in `deploy/deployment.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bmh-generator-config
  namespace: metal3-system
data:
  UCS_CENTRAL_IP: "10.0.0.1"  # Replace with your UCS Central IP
  DEFAULT_IPMI_USERNAME: "admin"  # Default IPMI username
  DEFAULT_IPMI_PASSWORD: "password"  # Default IPMI password
```

### 4. Deploy the Operator

```bash
kubectl apply -f deploy/deployment.yaml
```

### 5. Verify Installation

```bash
# Check if the operator is running
kubectl get pods -n metal3-system -l app=bmh-generator-operator

# Check operator logs
kubectl logs -n metal3-system -l app=bmh-generator-operator
```

## Usage

### Creating a BareMetalHostGenerator

Create a YAML file (e.g., `bmhgen-example.yaml`) with your server configuration:

```yaml
apiVersion: infra.example.com/v1alpha1
kind: BareMetalHostGenerator
metadata:
  name: ocp4-roi-compute01
  namespace: openshift-machine-api
spec:
  serverName: "compute-01"  # Name of server in UCS Central (optional, defaults to CR name)
  namespace: "openshift-machine-api"  # Target namespace for BareMetalHost
  infraEnv: "ocp4-roi"  # InfraEnv name for OpenShift Agent-based installation
  ipmiUsername: "admin"  # IPMI username (optional)
  ipmiPasswordSecret:  # Optional: reference to secret containing IPMI password
    name: "ipmi-credentials"
    key: "password"
  labels:  # Additional labels for the BareMetalHost
    node-role.kubernetes.io/worker: ""
    custom-label: "custom-value"
```

### Apply the Configuration

```bash
# Create the BareMetalHostGenerator
kubectl apply -f bmhgen-example.yaml

# Check status
kubectl get bmhgen -n openshift-machine-api

# Get detailed information
kubectl describe bmhgen ocp4-roi-compute01 -n openshift-machine-api

# Verify the BareMetalHost was created
kubectl get bmh -n openshift-machine-api

# Check the generated BareMetalHost details
kubectl describe bmh ocp4-roi-compute01 -n openshift-machine-api
```

### Monitoring Progress

The operator updates the status of the BareMetalHostGenerator resource:

```bash
# Watch the status in real-time
kubectl get bmhgen ocp4-roi-compute01 -n openshift-machine-api -w

# Check current status
kubectl get bmhgen ocp4-roi-compute01 -n openshift-machine-api -o yaml
```

Status phases:
- **Processing**: Operator is querying UCS Central and creating resources
- **Completed**: BareMetalHost successfully created
- **Failed**: Error occurred during processing

## Configuration Options

### BareMetalHostGenerator Spec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `serverName` | string | No | Name of the server in UCS Central (defaults to CR name) |
| `namespace` | string | No | Target namespace for BareMetalHost (defaults to current namespace) |
| `infraEnv` | string | Yes | InfraEnv name for OpenShift Agent-based installation |
| `ipmiUsername` | string | No | IPMI username (defaults to operator config) |
| `ipmiPasswordSecret` | object | No | Reference to secret containing IPMI password |
| `labels` | map | No | Additional labels to add to BareMetalHost |

### Environment Variables

The operator requires the following environment variables:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `UCS_CENTRAL_IP` | UCS Central IP address | - | Yes |
| `UCS_CENTRAL_USERNAME` | UCS Central username | `admin` | No |
| `UCS_CENTRAL_PASSWORD` | UCS Central password | - | Yes |
| `UCS_MANAGER_USERNAME` | UCS Manager username (for all managers) | `admin` | No |
| `UCS_MANAGER_PASSWORD` | UCS Manager password (for all managers) | - | Yes |
| `DEFAULT_IPMI_USERNAME` | Default IPMI username | `admin` | No |
| `DEFAULT_IPMI_PASSWORD` | Default IPMI password | `password` | No |

## Generated Resources

For each BareMetalHostGenerator, the operator creates:

1. **BareMetalHost**: The main Metal3 resource representing the bare metal server
2. **Secret**: BMC credentials for IPMI access (named `{server-name}-bmc-secret`)

### Example Generated BareMetalHost

```yaml
apiVersion: metal3.io/v1alpha1
kind: BareMetalHost
metadata:
  name: ocp4-roi-compute01
  namespace: openshift-machine-api
  labels:
    infraenvs.agent-install.openshift.io: ocp4-roi
  annotations:
    inspect.metal3.io: disabled
    bmac.agent-install.openshift.io/hostname: ocp4-roi-compute01
spec:
  online: true
  bootMACAddress: "aa:bb:cc:dd:ee:ff"
  automatedCleaningMode: disabled
  bmc:
    address: "ipmi://192.168.1.100"
    credentialsName: "ocp4-roi-compute01-bmc-secret"
    disableCertificateVerification: true
  bootMode: UEFI
```

## Troubleshooting

### Common Issues

1. **UCS Central Connection Errors**
   ```bash
   # Check operator logs
   kubectl logs -n metal3-system -l app=bmh-generator-operator
   
   # Verify UCS Central credentials
   kubectl get secret ucs-central-credentials -n metal3-system -o yaml
   
   # Check UCS Central IP configuration
   kubectl get configmap bmh-generator-config -n metal3-system -o yaml
   ```

2. **UCS Manager Connection Errors**
   ```bash
   # Check if the operator can reach UCS Managers through UCS Central
   kubectl logs -n metal3-system -l app=bmh-generator-operator | grep -i "domain"
   
   # Verify UCS Manager credentials
   kubectl get secret ucs-manager-credentials -n metal3-system -o yaml
   ```

3. **Server Not Found in UCS Central**
   ```bash
   # Check if the server name exists in UCS Central
   kubectl describe bmhgen <name> -n <namespace>
   
   # Verify the server is registered in UCS Central
   kubectl logs -n metal3-system -l app=bmh-generator-operator | grep -i "servers"
   ```

4. **Permission Errors**
   ```bash
   # Verify RBAC configuration
   kubectl auth can-i create baremetalhosts --as=system:serviceaccount:metal3-system:bmh-generator-operator
   ```

### Debug Commands

```bash
# Get all BareMetalHostGenerators
kubectl get bmhgen --all-namespaces

# Check operator status
kubectl get pods -n metal3-system
kubectl describe deployment bmh-generator-operator -n metal3-system

# View operator logs
kubectl logs -n metal3-system deployment/bmh-generator-operator -f

# Check UCS Central connectivity
kubectl logs -n metal3-system deployment/bmh-generator-operator | grep -i "ucs central"

# Check server discovery
kubectl logs -n metal3-system deployment/bmh-generator-operator | grep -i "found.*servers"
```

## Development

### Local Development

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set environment variables:
   ```bash
   export UCS_CENTRAL_IP="10.0.0.1"
   export UCS_CENTRAL_USERNAME="admin"
   export UCS_CENTRAL_PASSWORD="your-central-password"
   export UCS_MANAGER_USERNAME="admin"
   export UCS_MANAGER_PASSWORD="your-manager-password"
   export DEFAULT_IPMI_USERNAME="admin"
   export DEFAULT_IPMI_PASSWORD="password"
   ```

3. Run locally:
   ```bash
   kopf run --liveness=http://0.0.0.0:8080/healthz src/operator_bmh_gen.py --all-namespaces
   ```

### Testing UCS Connection

You can test the UCS client independently:

```python
from src.ucs_client import UCSClient

# Initialize the client
client = UCSClient(
    ucs_central_ip='10.0.0.1',
    central_username='admin',
    central_password='central-password',
    manager_username='admin',
    manager_password='manager-password'
)

# Connect and query
client.connect()
servers = client.get_all_servers()
print(f"Found {len(servers)} servers in UCS Central")

# Get specific server info
mac, ip = client.get_server_info('compute-01')
print(f"MAC: {mac}, IP: {ip}")

client.disconnect()
```

### Building the Container

```bash
# Build the container
docker build -t your-registry/bmh-generator-operator:latest .

# Push to registry
docker push your-registry/bmh-generator-operator:latest
```

## Security Considerations

- Store UCS Central and UCS Manager credentials in separate Kubernetes secrets
- Use least-privilege RBAC permissions
- Enable network policies to restrict operator communication
- Regularly rotate credentials for both UCS Central and UCS Managers
- Consider using external secret management solutions (e.g., HashiCorp Vault, AWS Secrets Manager)
- Ensure secure communication between the operator and UCS Central/Managers

## UCS Central Integration Details

The operator follows this workflow:
1. Connects to UCS Central using provided credentials
2. Queries all logical servers (`lsServer`) from UCS Central
3. For each requested server, finds the corresponding UCS Manager domain
4. Connects to the specific UCS Manager to retrieve detailed information
5. Extracts MAC address from VnicEther adapters
6. Extracts KVM/IPMI IP from VnicIpV4PooledAddr
7. Creates BareMetalHost resource with the gathered information

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
- Check the troubleshooting section above
- Review operator logs for detailed error messages
- Verify UCS Central and Manager connectivity
- Open an issue in the project repository