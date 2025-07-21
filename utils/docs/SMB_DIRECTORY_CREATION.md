# SMB Directory Creation Research

This document summarizes our research into proper directory creation with smbprotocol.

## Key Findings

### 1. Create Dispositions

The correct create disposition values for smbprotocol are:

```python
from smbprotocol.open import CreateDisposition

# Working dispositions for directory creation:
CreateDisposition.FILE_CREATE      # Value: 2 - Creates new directory, fails if exists
CreateDisposition.FILE_OPEN_IF     # Value: 3 - Creates if doesn't exist, opens if exists
CreateDisposition.FILE_SUPERSEDE   # Value: 0 - Creates new, overwrites if exists
CreateDisposition.FILE_OVERWRITE_IF # Value: 5 - Creates if doesn't exist, overwrites if exists

# Non-working dispositions for directory creation:
CreateDisposition.FILE_OPEN        # Value: 1 - Fails if doesn't exist
CreateDisposition.FILE_OVERWRITE   # Value: 4 - Fails if doesn't exist
```

### 2. Recommended Approach

For directory creation in setup/validation scenarios, use **`FILE_OPEN_IF` (value 3)**:

```python
dir_open.create(
    impersonation_level=0,  # SECURITY_ANONYMOUS
    desired_access=0x80000000,  # GENERIC_READ
    file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
    share_access=0x00000001,  # FILE_SHARE_READ
    create_disposition=3,  # FILE_OPEN_IF - works best for existing directories
    create_options=0x00000020  # FILE_DIRECTORY_FILE
)
```

### 3. SMB Server Limitations

**Nested Directory Creation**: Most SMB servers (including Samba) do not support creating nested directories in a single operation. You must create directories one level at a time.

**Example Failure**:
```
❌ Failed to create directory cache_volume\mgc: 
   STATUS_OBJECT_PATH_NOT_FOUND: 0xc000003a
```

**Workaround**: Create parent directories first, then child directories.

### 4. Implementation Strategy

For the setup command, we should:

1. **Sort directories by depth** (shallowest first)
2. **Create directories one level at a time**
3. **Use FILE_OPEN_IF** to handle existing directories gracefully
4. **Continue on errors** when `--force` is used
5. **Report partial success** when some directories can't be created

### 5. Test Results

Our testing showed:

- ✅ `FILE_OPEN_IF` works for creating new directories
- ✅ `FILE_OPEN_IF` works for opening existing directories  
- ❌ Nested directory creation fails with `STATUS_OBJECT_PATH_NOT_FOUND`
- ✅ Root-level directories can be created successfully
- ✅ Files in root directory can be created successfully

### 6. Current Implementation

The setup command now:

- Uses `FILE_OPEN_IF` (value 3) for directory creation
- Sorts directories by depth before creation
- Attempts to create directories one level at a time
- Reports partial success when some operations fail
- Provides `--dry-run` and `--force` options

### 7. Recommendations

1. **For setup**: Use `FILE_OPEN_IF` and handle nested directory limitations gracefully
2. **For validation**: Check what can be created vs. what's required
3. **For replay**: Ensure pre-trace state setup handles server limitations
4. **Documentation**: Inform users about SMB server limitations

### 8. Example Usage

```bash
# Dry run to see what would be created
smbreplay setup <session_id> --dry-run

# Actual setup (will show partial success)
smbreplay setup <session_id>

# Force setup (continue despite errors)
smbreplay setup <session_id> --force

# Validate after setup
smbreplay validate <session_id>
``` 