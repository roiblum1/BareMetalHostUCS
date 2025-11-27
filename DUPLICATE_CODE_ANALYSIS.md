# Duplicate Code & Code Quality Analysis

## Executive Summary

This document identifies duplicate code patterns, code quality issues, and opportunities for refactoring to improve maintainability and reduce technical debt.

---

## 🔍 DUPLICATE CODE PATTERNS

### 1. **Event Loop Pattern (4 duplicates)**

**Location**: `buffer_manager.py:59, 107, 143, 232`

**Duplicate Code**:
```python
# Pattern repeated 4 times
loop = asyncio.get_event_loop()
result = await loop.run_in_executor(
    None,
    lambda: self.custom_api.some_method(...)
)
```

**Impact**: 
- Code duplication
- Deprecated API usage
- Harder to maintain

**Refactoring**:
```python
# Create helper method in BufferManager
async def _run_k8s_api_call(self, func, *args, **kwargs):
    """Execute synchronous Kubernetes API call in executor"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

# Usage:
bmhs = await self._run_k8s_api_call(
    self.custom_api.list_cluster_custom_object,
    group="metal3.io",
    version="v1alpha1",
    plural="baremetalhosts"
)
```

**Files Affected**: `buffer_manager.py` (4 instances)

---

### 2. **Status Update Dictionary Creation (8 duplicates)**

**Location**: Multiple files

**Duplicate Pattern**:
```python
# Pattern 1: Completed status (3 duplicates)
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

# Pattern 2: Failed status (2 duplicates)
status_update = {
    "phase": "Failed",
    "message": str(e)
}

# Pattern 3: Buffered status (1 duplicate)
status_update = {
    "phase": "Buffered",
    "message": f"Server buffered...",
    "bufferedAt": datetime.utcnow().isoformat() + "Z",
    "macAddress": mac_address,
    "ipmiAddress": ip_address,
    "serverVendor": server_vendor,
    "vlanId": vlan_id
}
```

**Locations**:
- `operator_bmh_gen.py:199, 268, 287`
- `buffer_manager.py:206, 246, 303, 329, 417`

**Refactoring**:
```python
# Create StatusBuilder helper class
class StatusBuilder:
    @staticmethod
    def completed(server_name: str, target_namespace: str, 
                  mac_address: str, ip_address: str, 
                  server_vendor: str, vlan_id: Optional[str] = None) -> dict:
        """Build Completed status dictionary"""
        status = {
            "phase": "Completed",
            "message": f"Successfully created BareMetalHost {server_name}",
            "bmhName": server_name,
            "bmhNamespace": target_namespace,
            "macAddress": mac_address,
            "ipmiAddress": ip_address,
            "serverVendor": server_vendor,
        }
        if vlan_id:
            status["vlanId"] = vlan_id
        return status
    
    @staticmethod
    def failed(message: str, mac_address: Optional[str] = None,
               ip_address: Optional[str] = None,
               server_vendor: Optional[str] = None) -> dict:
        """Build Failed status dictionary"""
        status = {
            "phase": "Failed",
            "message": message
        }
        if mac_address:
            status["macAddress"] = mac_address
        if ip_address:
            status["ipmiAddress"] = ip_address
        if server_vendor:
            status["serverVendor"] = server_vendor
        return status
    
    @staticmethod
    def buffered(available_count: int, max_count: int,
                mac_address: str, ip_address: str,
                server_vendor: str, vlan_id: Optional[str] = None) -> dict:
        """Build Buffered status dictionary"""
        status = {
            "phase": "Buffered",
            "message": f"Server buffered (available: {available_count}/{max_count})",
            "bufferedAt": datetime.utcnow().isoformat() + "Z",
            "macAddress": mac_address,
            "ipmiAddress": ip_address,
            "serverVendor": server_vendor,
        }
        if vlan_id:
            status["vlanId"] = vlan_id
        return status
    
    @staticmethod
    def processing(server_name: str) -> dict:
        """Build Processing status dictionary"""
        return {
            "phase": "Processing",
            "message": f"Looking up server {server_name} in management systems."
        }
```

**Usage**:
```python
# Before:
status_update = {
    "phase": "Completed",
    "message": f"Successfully created BareMetalHost {server_name}",
    # ... 6 more lines
}

# After:
status_update = StatusBuilder.completed(
    server_name, target_namespace, mac_address, 
    ip_address, server_vendor, vlan_id
)
```

**Files Affected**: `operator_bmh_gen.py`, `buffer_manager.py`

---

### 3. **Status Field Extraction Pattern (15+ duplicates)**

**Location**: Multiple files

**Duplicate Pattern**:
```python
# Pattern repeated many times
status = bmhgen.get('status', {})
mac_address = status.get('macAddress')
ipmi_address = status.get('ipmiAddress')
server_vendor = status.get('serverVendor')
vlan_id = status.get('vlanId')

# Or:
annotations = bmhgen.get('metadata', {}).get('annotations', {})
server_vendor = annotations.get('server_vendor')
vlan_id = annotations.get('vlanId')
```

**Locations**:
- `operator_bmh_gen.py:190-191`
- `buffer_manager.py:179-198` (complex nested logic)

**Refactoring**:
```python
# Create helper class for extracting status fields
class StatusExtractor:
    @staticmethod
    def extract_server_info(bmhgen: dict) -> dict:
        """Extract server information from BMHGen resource"""
        status = bmhgen.get('status', {})
        metadata = bmhgen.get('metadata', {})
        annotations = metadata.get('annotations', {})
        spec = bmhgen.get('spec', {})
        
        # Extract from status first, fallback to annotations
        server_vendor = (
            status.get('serverVendor') or 
            annotations.get('server_vendor')
        )
        
        # If still not found, detect from name
        if not server_vendor:
            from src.server_strategy import ServerTypeDetector
            name = metadata.get('name', '')
            detected_type = ServerTypeDetector.detect(name)
            server_vendor = detected_type.value.upper()
        
        vlan_id = (
            status.get('vlanId') or 
            annotations.get('vlanId') or 
            ""
        )
        
        return {
            'mac_address': status.get('macAddress'),
            'ipmi_address': status.get('ipmiAddress'),
            'server_vendor': server_vendor,
            'vlan_id': vlan_id if vlan_id or server_vendor.upper() == 'DELL' else "",
            'server_name': spec.get('serverName', metadata.get('name')),
            'target_namespace': spec.get('namespace', metadata.get('namespace')),
            'infra_env': spec.get('infraEnv'),
            'labels': spec.get('labels', {}),
        }
```

**Usage**:
```python
# Before (15+ lines):
status = bmhgen.get('status', {})
mac_address = status.get('macAddress')
ipmi_address = status.get('ipmiAddress')
server_vendor = status.get('serverVendor')
if not server_vendor:
    annotations = bmhgen.get('metadata', {}).get('annotations', {})
    server_vendor = annotations.get('server_vendor')
    if not server_vendor:
        from src.server_strategy import ServerTypeDetector
        detected_type = ServerTypeDetector.detect(name)
        server_vendor = detected_type.value.upper()
# ... more extraction logic

# After (1 line):
info = StatusExtractor.extract_server_info(bmhgen)
```

**Files Affected**: `operator_bmh_gen.py`, `buffer_manager.py`

---

### 4. **OpenShiftUtils Call Pattern (13 duplicates)**

**Location**: Multiple files

**Duplicate Pattern**:
```python
# Pattern repeated 13 times
OpenShiftUtils.update_bmh_status(
    custom_api, "infra.example.com", "v1alpha1",
    namespace, "baremetalhostgenerators", name, status_update
)
```

**Magic Strings**: `"infra.example.com"`, `"v1alpha1"`, `"baremetalhostgenerators"` repeated

**Refactoring**:
```python
# Create constants
class BMHGenConstants:
    GROUP = "infra.example.com"
    VERSION = "v1alpha1"
    PLURAL = "baremetalhostgenerators"
    KIND = "BareMetalHostGenerator"

# Create wrapper method
class BMHGenUtils:
    @staticmethod
    def update_status(custom_api, namespace: str, name: str, 
                     status_update: dict) -> None:
        """Update BMHGen status with standard parameters"""
        OpenShiftUtils.update_bmh_status(
            custom_api, 
            BMHGenConstants.GROUP,
            BMHGenConstants.VERSION,
            namespace,
            BMHGenConstants.PLURAL,
            name,
            status_update
        )
```

**Usage**:
```python
# Before:
OpenShiftUtils.update_bmh_status(
    custom_api, "infra.example.com", "v1alpha1",
    namespace, "baremetalhostgenerators", name, status_update
)

# After:
BMHGenUtils.update_status(custom_api, namespace, name, status_update)
```

**Files Affected**: `operator_bmh_gen.py`, `buffer_manager.py`

---

### 5. **Error Handling Pattern (6+ duplicates)**

**Location**: Multiple files

**Duplicate Pattern**:
```python
# Pattern repeated in multiple places
try:
    # Some operation
except Exception as e:
    logger.error(f"Error message: {e}")
    # Try to update status to Failed
    try:
        status_update = {
            "phase": "Failed",
            "message": str(e)
        }
        OpenShiftUtils.update_bmh_status(...)
    except Exception as final_error:
        logger.critical(f"Could not update status: {final_error}")
    raise
```

**Refactoring**:
```python
# Create error handler decorator/context manager
from contextlib import contextmanager

@contextmanager
def handle_bmhgen_error(custom_api, namespace: str, name: str, 
                       operation: str):
    """Context manager for error handling with status updates"""
    try:
        yield
    except Exception as e:
        logger.error(f"Error in {operation} for {name}: {e}")
        try:
            BMHGenUtils.update_status(
                custom_api, namespace, name,
                StatusBuilder.failed(str(e))
            )
        except Exception as status_error:
            logger.critical(
                f"Could not update {name} to Failed status: {status_error}"
            )
        raise
```

**Usage**:
```python
# Before:
try:
    # operations
except Exception as e:
    logger.error(...)
    try:
        # update status
    except:
        logger.critical(...)
    raise

# After:
with handle_bmhgen_error(custom_api, namespace, name, "create_bmh"):
    # operations
```

**Files Affected**: `operator_bmh_gen.py`, `buffer_manager.py`

---

### 6. **Vendor Detection Logic (3 duplicates)**

**Location**: `operator_bmh_gen.py:217-219`, `buffer_manager.py:184-191`

**Duplicate Pattern**:
```python
# Pattern repeated
if not server_vendor:
    detected_type = unified_client._detector.detect(server_name)
    server_vendor = detected_type.name  # or .value.upper()
```

**Refactoring**: Already extracted to `StatusExtractor` (see #3)

---

### 7. **404 Error Handling Pattern (4 duplicates)**

**Location**: Multiple files

**Duplicate Pattern**:
```python
# Pattern repeated
except Exception as e:
    if hasattr(e, 'status') and e.status == 404:
        logger.error("Resource not found...")
        return []  # or return False, or continue
    raise
```

**Refactoring**:
```python
# Create helper function
def handle_404_error(e: Exception, resource_type: str, 
                    default_return=None):
    """Handle 404 errors consistently"""
    if hasattr(e, 'status') and e.status == 404:
        logger.error(f"{resource_type} CRD not found. "
                    f"Ensure that the operator is installed.")
        return default_return
    raise
```

**Usage**:
```python
# Before:
except Exception as e:
    if hasattr(e, 'status') and e.status == 404:
        logger.error("BareMetalHost CRD not found...")
        return []
    raise

# After:
except Exception as e:
    return handle_404_error(e, "BareMetalHost", default_return=[])
```

**Files Affected**: `buffer_manager.py` (4 instances)

---

## 📝 CODE QUALITY ISSUES

### 1. **Magic Strings**

**Issue**: Hardcoded strings repeated throughout codebase

**Examples**:
- `"infra.example.com"` (13 occurrences)
- `"v1alpha1"` (13 occurrences)
- `"baremetalhostgenerators"` (13 occurrences)
- `"metal3.io"` (multiple occurrences)
- `"Completed"`, `"Failed"`, `"Buffered"`, `"Processing"` (10+ occurrences)

**Fix**: Extract to constants module

```python
# constants.py
class CRDConstants:
    BMHGEN_GROUP = "infra.example.com"
    BMHGEN_VERSION = "v1alpha1"
    BMHGEN_PLURAL = "baremetalhostgenerators"
    BMHGEN_KIND = "BareMetalHostGenerator"
    
    BMH_GROUP = "metal3.io"
    BMH_VERSION = "v1alpha1"
    BMH_PLURAL = "baremetalhosts"
    BMH_KIND = "BareMetalHost"

class Phase:
    PROCESSING = "Processing"
    BUFFERED = "Buffered"
    COMPLETED = "Completed"
    FAILED = "Failed"
```

---

### 2. **Inconsistent Error Messages**

**Issue**: Similar errors have different message formats

**Examples**:
- `f"Error processing BareMetalHostGenerator {name}: {e}"`
- `f"Error in buffer check iteration: {e}"`
- `f"Error getting server info for {name}: {str(e)}"`

**Fix**: Standardize error message format

```python
# Create error formatter
def format_error(operation: str, resource: str = None, 
                error: Exception = None) -> str:
    """Format error messages consistently"""
    parts = [f"Error in {operation}"]
    if resource:
        parts.append(f"for {resource}")
    if error:
        parts.append(f": {error}")
    return " ".join(parts)
```

---

### 3. **Long Methods**

**Issue**: Methods exceed 50 lines, doing multiple things

**Examples**:
- `create_bmh()`: ~150 lines
- `process_buffered_generator()`: ~180 lines
- `buffer_check_iteration()`: ~50 lines

**Fix**: Extract methods

```python
# Break down create_bmh into smaller methods
async def create_bmh(...):
    _validate_spec(spec, name)
    _patch_server_name_if_needed(...)
    server_info = await _get_server_info(...)
    if await _should_buffer(...):
        return
    await _create_resources(...)
    await _update_status_completed(...)
```

---

### 4. **Inconsistent Naming**

**Issue**: Variable names inconsistent

**Examples**:
- `server_name` vs `name` vs `bmh_name`
- `ip_address` vs `ipmi_address` vs `ip`
- `server_vendor` vs `vendor`

**Fix**: Standardize naming conventions

---

### 5. **Missing Type Hints**

**Issue**: Some methods lack type hints

**Examples**:
- `_extract_hp_management_ip(self, server)` - no return type
- `_extract_hp_mac_address(self, server_hardware)` - no return type

**Fix**: Add type hints everywhere

```python
def _extract_hp_management_ip(self, server: dict) -> Optional[str]:
    ...
```

---

### 6. **Inconsistent Logging**

**Issue**: Logging levels and formats inconsistent

**Examples**:
- Some use `logger.info()`, others use `logger.debug()`
- Some include context, others don't
- F-string usage inconsistent

**Fix**: Create logging helpers

```python
def log_operation(logger, level: str, operation: str, 
                 resource: str = None, **kwargs):
    """Standardized logging"""
    message_parts = [operation]
    if resource:
        message_parts.append(f"for {resource}")
    if kwargs:
        details = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        message_parts.append(f"({details})")
    
    getattr(logger, level)(" ".join(message_parts))
```

---

## 🔧 REFACTORING PRIORITIES

### Priority 1: High Impact, Low Risk

1. **Extract StatusBuilder** (8 duplicates → 1 class)
   - Reduces code duplication significantly
   - Makes status updates consistent
   - Easy to test

2. **Extract StatusExtractor** (15+ duplicates → 1 method)
   - Eliminates complex nested extraction logic
   - Single source of truth for field extraction
   - Reduces bugs from inconsistent extraction

3. **Create Constants Module** (30+ magic strings → constants)
   - Prevents typos
   - Easy to update if CRD changes
   - Better IDE support

### Priority 2: Medium Impact, Medium Risk

4. **Extract Event Loop Helper** (4 duplicates → 1 method)
   - Fixes deprecated API usage
   - Consistent error handling
   - Easier to add timeouts/retries

5. **Create BMHGenUtils Wrapper** (13 duplicates → wrapper)
   - Reduces magic string repetition
   - Easier to maintain
   - Can add validation/logging

### Priority 3: Low Impact, High Risk

6. **Refactor Long Methods** (3 methods)
   - Improves readability
   - Easier to test
   - But requires careful testing

7. **Standardize Error Handling** (6+ patterns)
   - Consistent error handling
   - Better error messages
   - But changes many code paths

---

## 📊 METRICS

### Code Duplication

| Pattern | Occurrences | Lines Saved | Risk |
|---------|------------|-------------|------|
| Status Update Dict | 8 | ~80 | Low |
| Status Extraction | 15+ | ~150 | Low |
| Event Loop Pattern | 4 | ~20 | Low |
| OpenShiftUtils Calls | 13 | ~65 | Low |
| Error Handling | 6+ | ~60 | Medium |
| **Total** | **46+** | **~375** | **Low-Medium** |

### Code Quality Issues

| Issue | Count | Severity |
|-------|-------|----------|
| Magic Strings | 30+ | Medium |
| Long Methods | 3 | Medium |
| Missing Type Hints | 10+ | Low |
| Inconsistent Naming | 15+ | Low |
| Inconsistent Logging | 20+ | Low |

---

## ✅ RECOMMENDED ACTIONS

### Immediate (This Sprint)

1. ✅ Create `constants.py` with all magic strings
2. ✅ Create `StatusBuilder` class
3. ✅ Create `StatusExtractor` class
4. ✅ Extract event loop helper method

### Short Term (Next Sprint)

5. Create `BMHGenUtils` wrapper
6. Standardize error handling
7. Add missing type hints
8. Refactor long methods

### Long Term (Future)

9. Migrate to async HTTP (eliminates executor pattern)
10. Add comprehensive unit tests
11. Implement code quality gates (linting, type checking)

---

**Generated**: $(date)
**Files Analyzed**: 8
**Duplicate Patterns Found**: 7
**Estimated Lines Saved**: ~375
**Refactoring Risk**: Low-Medium

