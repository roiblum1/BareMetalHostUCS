# BareMetalHost Generator Operator

A Kubernetes operator that automatically creates BareMetalHost resources by querying Cisco UCS (Unified Computing System) for server information. This operator simplifies the process of onboarding bare metal servers into Metal3 and OpenShift bare metal deployments.

## Overview

The BareMetalHostGenerator operator:
- Queries Cisco UCS for server MAC addresses and IPMI information
- Automatically creates BareMetalHost resources with the retrieved data
- Generates BMC secrets for IPMI authentication
- Integrates with OpenShift Agent-based Installation workflows

## Architecture

The operator consists of:
- **Custom Resource Definition (CRD)**: `BareMetalHostGenerator` - defines the desired server configuration
- **Controller**: Watches for CRD creation and handles the server lookup and BMH creation
- **UCS Client**: Interfaces with Cisco UCS to retrieve server information

## Prerequisites

- Kubernetes cluster with Metal3 installed
- Cisco UCS environment with API access
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

Edit `deploy/deployment.yaml` and update the following values:

```yaml
stringData:
  username: "your-ucs-username"  # Replace with your UCS username
  password: "your-ucs-password"  # Replace with your UCS password
```

```yaml
data:
  UCS_ENDPOINT: "https://your-ucs-endpoint.example.com"  # Replace with your UCS endpoint
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
  serverName: "compute-01"  # Name of server in UCS (optional, defaults to CR name)
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
- **Processing**: Operator is querying UCS and creating resources
- **Completed**: BareMetalHost successfully created
- **Failed**: Error occurred during processing

## Configuration Options

### BareMetalHostGenerator Spec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `serverName` | string | No | Name of the server in UCS (defaults to CR name) |
| `namespace` | string | No | Target namespace for BareMetalHost (defaults to current namespace) |
| `infraEnv` | string | Yes | InfraEnv name for OpenShift Agent-based installation |
| `ipmiUsername` | string | No | IPMI username (defaults to operator config) |
| `ipmiPasswordSecret` | object | No | Reference to secret containing IPMI password |
| `labels` | map | No | Additional labels to add to BareMetalHost |

### Environment Variables

The operator accepts the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `UCS_ENDPOINT` | UCS Manager endpoint URL | `https://ucs.example.com` |
| `UCS_USERNAME` | UCS username | `admin` |
| `UCS_PASSWORD` | UCS password | `password` |
| `DEFAULT_IPMI_USERNAME` | Default IPMI username | `admin` |
| `DEFAULT_IPMI_PASSWORD` | Default IPMI password | `password` |

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

1. **UCS Connection Errors**
   ```bash
   # Check operator logs
   kubectl logs -n metal3-system -l app=bmh-generator-operator
   
   # Verify UCS credentials
   kubectl get secret ucs-credentials -n metal3-system -o yaml
   ```

2. **Server Not Found in UCS**
   ```bash
   # Check if the server name exists in UCS
   kubectl describe bmhgen <name> -n <namespace>
   ```

3. **Permission Errors**
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
```

## Development

### Local Development

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set environment variables:
   ```bash
   export UCS_ENDPOINT="https://your-ucs.example.com"
   export UCS_USERNAME="your-username"
   export UCS_PASSWORD="your-password"
   ```

3. Run locally:
   ```bash
   kopf run --liveness=http://0.0.0.0:8080/healthz src/operator.py --all-namespaces
   ```

### Building the Container

```bash
# Build the container
docker build -t your-registry/bmh-generator-operator:latest .

# Push to registry
docker push your-registry/bmh-generator-operator:latest
```

## Security Considerations

- Store UCS and IPMI credentials in Kubernetes secrets
- Use least-privilege RBAC permissions
- Enable network policies to restrict operator communication
- Regularly rotate credentials
- Consider using external secret management solutions

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
- Open an issue in the project repository