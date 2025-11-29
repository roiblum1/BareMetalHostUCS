# Constants Usage Guide

## Overview

All magic strings have been moved to `src/config.py` as constants. This eliminates typos, makes updates easier, and improves code maintainability.

## Available Constants

### 1. BareMetalHostGenerator CRD Constants

```python
from src.config import BMHGenCRD

# Usage:
BMHGenCRD.GROUP          # "infra.example.com"
BMHGenCRD.VERSION        # "v1alpha1"
BMHGenCRD.PLURAL         # "baremetalhostgenerators"
BMHGenCRD.KIND           # "BareMetalHostGenerator"
BMHGenCRD.FINALIZER      # "bmhgenerator.infra.example.com/finalizer"
```

**Example**:
```python
# Before:
custom_api.list_cluster_custom_object(
    group="infra.example.com",
    version="v1alpha1",
    plural="baremetalhostgenerators"
)

# After:
from src.config import BMHGenCRD
custom_api.list_cluster_custom_object(
    group=BMHGenCRD.GROUP,
    version=BMHGenCRD.VERSION,
    plural=BMHGenCRD.PLURAL
)
```

### 2. BareMetalHost CRD Constants

```python
from src.config import BMHCRD

# Usage:
BMHCRD.GROUP             # "metal3.io"
BMHCRD.VERSION           # "v1alpha1"
BMHCRD.PLURAL            # "baremetalhosts"
BMHCRD.KIND              # "BareMetalHost"
```

**Example**:
```python
# Before:
custom_api.list_cluster_custom_object(
    group="metal3.io",
    version="v1alpha1",
    plural="baremetalhosts"
)

# After:
from src.config import BMHCRD
custom_api.list_cluster_custom_object(
    group=BMHCRD.GROUP,
    version=BMHCRD.VERSION,
    plural=BMHCRD.PLURAL
)
```

### 3. NMStateConfig CRD Constants

```python
from src.config import NMStateConfigCRD

# Usage:
NMStateConfigCRD.GROUP   # "agent-install.openshift.io"
NMStateConfigCRD.VERSION # "v1beta1"
NMStateConfigCRD.PLURAL  # "nmstateconfigs"
NMStateConfigCRD.KIND    # "NMStateConfig"
```

### 4. Status Phase Constants

```python
from src.config import Phase

# Usage:
Phase.PROCESSING         # "Processing"
Phase.BUFFERED           # "Buffered"
Phase.COMPLETED          # "Completed"
Phase.FAILED             # "Failed"
```

**Example**:
```python
# Before:
status_update = {
    "phase": "Completed",
    "message": "..."
}

# After:
from src.config import Phase
status_update = {
    "phase": Phase.COMPLETED,
    "message": "..."
}
```

### 5. Annotation Key Constants

```python
from src.config import Annotations

# Usage:
Annotations.SERVER_VENDOR        # "server_vendor"
Annotations.VLAN_ID              # "vlanId"
Annotations.INSPECT_DISABLED     # "inspect.metal3.io"
Annotations.INFRA_ENV_LABEL      # "infraenvs.agent-install.openshift.io"
Annotations.HOSTNAME_ANNOTATION  # "bmac.agent-install.openshift.io/hostname"
```

**Example**:
```python
# Before:
server_vendor = annotations.get('server_vendor')
vlan_id = annotations.get('vlanId')

# After:
from src.config import Annotations
server_vendor = annotations.get(Annotations.SERVER_VENDOR)
vlan_id = annotations.get(Annotations.VLAN_ID)
```

## Migration Checklist

To migrate existing code to use constants:

- [ ] Import constants: `from src.config import BMHGenCRD, BMHCRD, Phase, Annotations`
- [ ] Replace `"infra.example.com"` with `BMHGenCRD.GROUP`
- [ ] Replace `"v1alpha1"` with `BMHGenCRD.VERSION` or `BMHCRD.VERSION`
- [ ] Replace `"baremetalhostgenerators"` with `BMHGenCRD.PLURAL`
- [ ] Replace `"metal3.io"` with `BMHCRD.GROUP`
- [ ] Replace `"baremetalhosts"` with `BMHCRD.PLURAL`
- [ ] Replace `"Processing"` with `Phase.PROCESSING`
- [ ] Replace `"Buffered"` with `Phase.BUFFERED`
- [ ] Replace `"Completed"` with `Phase.COMPLETED`
- [ ] Replace `"Failed"` with `Phase.FAILED`
- [ ] Replace `"server_vendor"` with `Annotations.SERVER_VENDOR`
- [ ] Replace `"vlanId"` with `Annotations.VLAN_ID`

## Benefits

1. **Type Safety**: IDE autocomplete and type checking
2. **No Typos**: Compile-time errors instead of runtime errors
3. **Easy Updates**: Change constant value in one place
4. **Better Documentation**: Constants are self-documenting
5. **Refactoring**: Easier to find all usages

## Files That Need Migration

- `src/operator_bmh_gen.py` (13 occurrences)
- `src/buffer_manager.py` (15+ occurrences)
- `src/openshift_utils.py` (6 occurrences)
- `src/yaml_generators.py` (3 occurrences)

**Total**: ~37 magic strings to replace
