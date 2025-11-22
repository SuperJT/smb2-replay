# SMBReplay Tool - Visual Usage Guide

## Quick Start Workflow

```
┌────────────────────────────────────────────────────────────────────────┐
│                    SMBReplay Tool Workflow                             │
└────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 1: INITIAL SETUP (One-Time Configuration)                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Commands:                                                              │
│    smbreplay config set server_ip <IP_ADDRESS>                         │
│    smbreplay config set domain <DOMAIN>                                │
│    smbreplay config set username <USERNAME>                            │
│    smbreplay config set tree_name <SHARE_NAME>                         │
│    smbreplay config set case_id <CASE_ID>                              │
│                                                                         │
│  Example:                                                               │
│    smbreplay config set server_ip 192.168.1.100                        │
│    smbreplay config set domain contoso.local                           │
│    smbreplay config set username testuser                              │
│    smbreplay config set tree_name testshare                            │
│    smbreplay config set case_id 20250122                               │
│                                                                         │
│  Verify:                                                                │
│    smbreplay config show                                               │
│                                                                         │
│  Storage: ~/.config/smbreplay/config.pkl (Linux/macOS)                 │
│           %LOCALAPPDATA%\smbreplay\config.pkl (Windows)                │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 2: DISCOVER AVAILABLE PCAP FILES                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Command:                                                               │
│    smbreplay list traces --case <CASE_ID>                              │
│                                                                         │
│  Example:                                                               │
│    smbreplay list traces --case 20250122                               │
│                                                                         │
│  Output:                                                                │
│    Available PCAP files:                                               │
│      - network_capture_01.pcap                                         │
│      - smb_session_morning.pcap                                        │
│      - file_transfer_test.pcap                                         │
│                                                                         │
│  Note: PCAP files should be in ~/cases/<CASE_ID>/traces/               │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 3: INGEST & PARSE PCAP FILE                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Command:                                                               │
│    smbreplay ingest --trace "<PCAP_FILENAME>"                          │
│                                                                         │
│  Options:                                                               │
│    --force              Force re-ingestion if already processed        │
│    --reassembly         Enable TCP reassembly for fragmented packets   │
│                                                                         │
│  Example:                                                               │
│    smbreplay ingest --trace "network_capture_01.pcap"                  │
│                                                                         │
│  What Happens:                                                          │
│    ┌──────────────┐                                                    │
│    │ PCAP File    │                                                    │
│    └──────┬───────┘                                                    │
│           │                                                             │
│           ↓                                                             │
│    ┌──────────────┐                                                    │
│    │  tshark      │ ← Extract SMB2 packets                            │
│    │  Processor   │   Filter: smb2 protocol                           │
│    └──────┬───────┘                                                    │
│           │                                                             │
│           ↓                                                             │
│    ┌──────────────┐                                                    │
│    │  Normalize   │ ← Convert hex IDs, status codes                   │
│    │  Fields      │   Parse file paths, commands                      │
│    └──────┬───────┘                                                    │
│           │                                                             │
│           ↓                                                             │
│    ┌──────────────┐                                                    │
│    │  Group by    │ ← Separate sessions by smb2.sesid                 │
│    │  Session ID  │                                                    │
│    └──────┬───────┘                                                    │
│           │                                                             │
│           ↓                                                             │
│    ┌──────────────┐                                                    │
│    │  Save to     │ ← Parquet files + JSON metadata                   │
│    │  Storage     │                                                    │
│    └──────────────┘                                                    │
│                                                                         │
│  Output Location:                                                       │
│    ~/cases/<CASE_ID>/.tracer/<PCAP>/<smb2_session_*.parquet>          │
│    ~/cases/<CASE_ID>/.tracer/<PCAP>/session_metadata.json             │
│                                                                         │
│  Output:                                                                │
│    Extracted 3 sessions:                                               │
│      - 0x7602000009fbdaa3 (156 operations)                            │
│      - 0x7602000009fbdaa4 (89 operations)                             │
│      - 0x7602000009fbdaa5 (42 operations)                             │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 4: ANALYZE SESSIONS                                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  List All Sessions:                                                     │
│    smbreplay session --list                                            │
│                                                                         │
│  View Session Summary:                                                  │
│    smbreplay session <SESSION_ID> --brief                              │
│                                                                         │
│  View Full Session Details:                                            │
│    smbreplay session <SESSION_ID>                                      │
│                                                                         │
│  Filter by File:                                                        │
│    smbreplay session <SESSION_ID> --file-filter "document.txt"         │
│                                                                         │
│  Example:                                                               │
│    smbreplay session 0x7602000009fbdaa3 --brief                        │
│                                                                         │
│  Output Shows:                                                          │
│    ┌─────┬──────────────┬──────────────┬────────────┐                │
│    │Frame│ Command      │ File         │ Status     │                │
│    ├─────┼──────────────┼──────────────┼────────────┤                │
│    │ 1234│ Negotiate    │ -            │ Success    │                │
│    │ 1235│ SessionSetup │ -            │ Success    │                │
│    │ 1236│ TreeConnect  │ -            │ Success    │                │
│    │ 1237│ Create       │ report.docx  │ Success    │                │
│    │ 1238│ Read         │ report.docx  │ 4096 bytes │                │
│    │ 1239│ Write        │ report.docx  │ 8192 bytes │                │
│    │ 1240│ Close        │ report.docx  │ Success    │                │
│    └─────┴──────────────┴──────────────┴────────────┘                │
│                                                                         │
│  Analysis Questions to Answer:                                         │
│    ✓ What files were accessed?                                        │
│    ✓ What operations were performed?                                  │
│    ✓ Were there any errors in the original capture?                   │
│    ✓ What's the sequence of operations?                               │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 5: VALIDATE REPLAY READINESS (Optional but Recommended)           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Command:                                                               │
│    smbreplay validate <SESSION_ID>                                     │
│                                                                         │
│  Options:                                                               │
│    --check-fs        Validate file system on target server             │
│    --check-ops       Check operation validity                          │
│                                                                         │
│  Example:                                                               │
│    smbreplay validate 0x7602000009fbdaa3 --check-fs                    │
│                                                                         │
│  Checks:                                                                │
│    ✓ Target server connectivity (server_ip)                           │
│    ✓ Authentication credentials (domain, username, password)           │
│    ✓ Share accessibility (tree_name)                                   │
│    ✓ File system permissions                                          │
│    ✓ Operation support on target server                               │
│                                                                         │
│  Output:                                                                │
│    Target server: 192.168.1.100                                        │
│    User: testuser@contoso.local                                        │
│    Share: testshare                                                     │
│    Readiness: ✓ OK                                                     │
│         OR                                                              │
│    Readiness: ✗ FAILED - Share not accessible                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 6: SETUP FILE SYSTEM (Optional)                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Command:                                                               │
│    smbreplay setup <SESSION_ID>                                        │
│                                                                         │
│  Options:                                                               │
│    --dry-run         Preview changes without executing                 │
│    --force           Override existing files/directories               │
│                                                                         │
│  Example:                                                               │
│    smbreplay setup 0x7602000009fbdaa3 --dry-run                        │
│                                                                         │
│  What It Does:                                                          │
│    1. Connects to target SMB server                                    │
│    2. Analyzes session for required directory structure                │
│    3. Cleans up existing files that will be recreated                  │
│    4. Creates necessary directory hierarchy                            │
│                                                                         │
│  Output:                                                                │
│    Connecting to 192.168.1.100...                                      │
│    Analyzing session 0x7602000009fbdaa3...                             │
│    Cleanup plan:                                                        │
│      - Delete /documents/report.docx                                   │
│      - Delete /data/output.txt                                         │
│    Directory structure:                                                 │
│      + Create /documents/                                              │
│      + Create /data/archive/                                           │
│    Ready for replay                                                     │
│                                                                         │
│  When to Use:                                                           │
│    • First-time replay of a session                                    │
│    • After manual changes to target server                             │
│    • When replay fails due to missing directories                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 7: REPLAY SESSION                                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Command:                                                               │
│    smbreplay replay <SESSION_ID>                                       │
│                                                                         │
│  Options:                                                               │
│    --server-ip <IP>      Override configured server IP                 │
│    --domain <DOMAIN>     Override configured domain                    │
│    --username <USER>     Override configured username                  │
│    --password <PASS>     Provide password (prompts if not given)       │
│    --tree-name <SHARE>   Override configured share name                │
│    --validate            Validate readiness before replay              │
│    --no-ping             Skip initial ping to server                   │
│    -v, -vv, -vvv         Increase verbosity (debug output)             │
│                                                                         │
│  Example:                                                               │
│    smbreplay replay 0x7602000009fbdaa3 --validate                      │
│                                                                         │
│  Execution Flow:                                                        │
│    ┌──────────────────────────────────────────────────┐               │
│    │ 1. Load Session from Parquet                     │               │
│    └────────────┬─────────────────────────────────────┘               │
│                 ↓                                                       │
│    ┌──────────────────────────────────────────────────┐               │
│    │ 2. Connect to SMB Server                         │               │
│    │    • Negotiate Protocol                          │               │
│    │    • Session Setup (Authentication)              │               │
│    │    • Tree Connect (Share Mount)                  │               │
│    └────────────┬─────────────────────────────────────┘               │
│                 ↓                                                       │
│    ┌──────────────────────────────────────────────────┐               │
│    │ 3. Initialize ID Mappings                        │               │
│    │    Original Session ID → Replay Session ID       │               │
│    │    Original Tree ID → Replay Tree ID             │               │
│    │    Original File IDs → Replay File Handles       │               │
│    └────────────┬─────────────────────────────────────┘               │
│                 ↓                                                       │
│    ┌──────────────────────────────────────────────────┐               │
│    │ 4. Execute Operations Sequentially               │               │
│    │    For each operation:                           │               │
│    │      a. Load captured parameters                 │               │
│    │      b. Map IDs (session, tree, file)            │               │
│    │      c. Call operation handler                   │               │
│    │      d. Validate response                        │               │
│    │      e. Log result (success/failure)             │               │
│    └────────────┬─────────────────────────────────────┘               │
│                 ↓                                                       │
│    ┌──────────────────────────────────────────────────┐               │
│    │ 5. Cleanup                                       │               │
│    │    • Close open file handles                     │               │
│    │    • Disconnect tree                             │               │
│    │    • Logoff session                              │               │
│    └────────────┬─────────────────────────────────────┘               │
│                 ↓                                                       │
│    ┌──────────────────────────────────────────────────┐               │
│    │ 6. Generate Report                               │               │
│    └──────────────────────────────────────────────────┘               │
│                                                                         │
│  Output:                                                                │
│    Sending replay start ping to 192.168.1.100                          │
│    Connecting to server...                                             │
│    Authenticated as: testuser@contoso.local                            │
│    Replaying 156 operations...                                         │
│                                                                         │
│    Progress: [████████████████████████████] 100%                      │
│                                                                         │
│    Operation Summary:                                                   │
│      ✓ Success: 154                                                    │
│      ✗ Failed: 2                                                       │
│        - Frame 1245: Read - Timeout                                    │
│        - Frame 1255: Write - Access denied                             │
│                                                                         │
│    Execution time: 2m 30s                                              │
│    Data transferred: 156.3 MB                                          │
│                                                                         │
│  Supported Operations:                                                  │
│    • Negotiate, SessionSetup, TreeConnect                              │
│    • Create, Close, Read, Write                                        │
│    • Lock, QueryInfo, SetInfo                                          │
│    • QueryDirectory, ChangeNotify                                      │
│    • IOCTL, Echo, Flush                                                │
│    • OplockBreak, LeaseBreak                                           │
│    • Cancel, Logoff                                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SMBReplay Architecture                           │
└─────────────────────────────────────────────────────────────────────────┘

INPUT                    PROCESSING                      OUTPUT
┌──────────┐            ┌──────────────┐               ┌──────────────┐
│          │            │              │               │              │
│  PCAP    │───────────→│  Ingestion   │──────────────→│  Session     │
│  Files   │            │  Engine      │               │  Parquet     │
│          │            │              │               │  Files       │
│          │            │  - tshark    │               │              │
│          │            │  - normalize │               │  + Metadata  │
│          │            │  - group     │               │    JSON      │
└──────────┘            └──────────────┘               └──────┬───────┘
                                                               │
                                                               │
                                                               ↓
                        ┌──────────────┐               ┌──────────────┐
                        │              │               │              │
                        │  Session     │←──────────────│  Session     │
                        │  Manager     │               │  Analysis    │
                        │              │               │  CLI         │
                        │  - load      │               │              │
                        │  - filter    │               │  - list      │
                        │  - format    │               │  - view      │
                        └──────┬───────┘               │  - filter    │
                               │                       └──────────────┘
                               │
                               ↓
                        ┌──────────────┐
                        │              │
                        │  SMB2        │
                        │  Replayer    │
                        │              │
                        │  - connect   │
                        │  - map IDs   │
                        │  - execute   │
                        │  - validate  │
                        └──────┬───────┘
                               │
                               ↓
                        ┌──────────────┐
                        │              │
                        │  Operation   │
                        │  Handlers    │
                        │              │
                        │  - create    │
                        │  - read      │
                        │  - write     │
                        │  - query     │
                        │  - ioctl     │
                        │  - etc...    │
                        └──────┬───────┘
                               │
                               ↓
                        ┌──────────────┐
                        │              │
                        │ smbprotocol  │
                        │ Library      │
                        │              │
                        └──────┬───────┘
                               │
                               ↓
                        ┌──────────────┐
                        │              │
                        │  Target SMB  │
                        │  Server      │
                        │              │
                        └──────────────┘
```

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Data Flow Diagram                             │
└─────────────────────────────────────────────────────────────────────────┘

1. CAPTURE PHASE (External to Tool)
   ┌─────────────┐
   │ Production  │
   │ SMB Server  │──→ Network Traffic ──→ Wireshark/tcpdump
   └─────────────┘                               ↓
                                          [ capture.pcap ]


2. INGESTION PHASE
   [ capture.pcap ]
          ↓
   ┌──────────────────────────────────────┐
   │ tshark -r capture.pcap -Y smb2       │
   │ -T fields -e frame.number            │
   │ -e smb2.sesid -e smb2.cmd ...        │
   └──────────────┬───────────────────────┘
                  ↓
          [ Raw TSV Output ]
                  ↓
   ┌──────────────────────────────────────┐
   │ Field Normalization:                 │
   │ • 0x0000000000000001 → 1 (sesid)     │
   │ • 0x05 → Create (cmd)                │
   │ • STATUS_SUCCESS → Success           │
   └──────────────┬───────────────────────┘
                  ↓
          [ Normalized DataFrame ]
                  ↓
   ┌──────────────────────────────────────┐
   │ Group by smb2.sesid                  │
   └──────────────┬───────────────────────┘
                  ↓
   ┌─────────────────────────────────────────────────────┐
   │ Session 0x01 │ Session 0x02 │ Session 0x03 │ ...   │
   │ (156 ops)    │ (89 ops)     │ (42 ops)     │       │
   └──────┬───────┴──────┬───────┴──────┬───────┴───────┘
          ↓              ↓              ↓
   [ session_01.parquet ][ session_02.parquet ][ session_03.parquet ]
          +              +              +
   [ session_metadata.json ]


3. ANALYSIS PHASE
   [ session_*.parquet ]
          ↓
   ┌──────────────────────────────────────┐
   │ Load into pandas DataFrame           │
   └──────────────┬───────────────────────┘
                  ↓
   ┌──────────────────────────────────────┐
   │ Filter, Format, Display              │
   │ • List all sessions                  │
   │ • Show operations per session        │
   │ • Filter by file/command             │
   └──────────────┬───────────────────────┘
                  ↓
          [ CLI Output Tables ]


4. REPLAY PHASE
   [ session_*.parquet ]
          ↓
   ┌──────────────────────────────────────┐
   │ Load Operations Sequentially         │
   └──────────────┬───────────────────────┘
                  ↓
   ┌──────────────────────────────────────┐
   │ For each operation:                  │
   │   1. Parse captured data             │
   │   2. Map original IDs → replay IDs   │
   │   3. Call handler                    │
   │   4. Execute via smbprotocol         │
   │   5. Validate response               │
   └──────────────┬───────────────────────┘
                  ↓
          [ SMB2 Protocol Packets ]
                  ↓
   ┌─────────────────────────────────────┐
   │ Target Lab SMB Server               │
   │ • Files created/modified            │
   │ • Same operations as production     │
   └─────────────────────────────────────┘
```

## Common Use Cases

### Use Case 1: Debug File Access Issue
```
Problem: User reports file access denied on production server
Goal: Reproduce issue in lab environment

Steps:
1. Capture SMB traffic during user's file access attempt (Wireshark)
2. Save PCAP: "file_access_issue.pcap"
3. Configure SMBReplay to point to lab server
4. Ingest PCAP: smbreplay ingest --trace "file_access_issue.pcap"
5. Analyze session to find access denied frame
6. Replay session on lab server with same user/permissions
7. Observe if issue reproduces
8. Modify lab permissions to test fixes
9. Re-replay to validate fix
```

### Use Case 2: Performance Testing
```
Problem: Need to test server performance under specific workload
Goal: Replay production traffic patterns on test server

Steps:
1. Capture SMB traffic during peak usage (PCAP)
2. Ingest multiple sessions from capture
3. Analyze sessions to identify representative workload
4. Setup test server with SMBReplay configuration
5. Replay sessions while monitoring server metrics
6. Compare performance vs. production baseline
7. Tune server configuration
8. Re-replay to measure improvements
```

### Use Case 3: Protocol Analysis
```
Problem: Understand how application interacts with SMB
Goal: Document operation sequence for specific file operations

Steps:
1. Capture application's SMB traffic
2. Ingest PCAP file
3. List sessions to identify relevant session
4. View session details: smbreplay session <ID>
5. Analyze operation sequence, parameters, responses
6. Document findings
7. Optionally replay to verify understanding
```

## Troubleshooting Guide

### Problem: tshark not found
```
Error: tshark command not available
Solution:
  - Install Wireshark (includes tshark)
  - Linux: sudo apt-get install tshark
  - macOS: brew install wireshark
  - Windows: Download from wireshark.org
```

### Problem: Authentication failed during replay
```
Error: STATUS_LOGON_FAILURE
Solution:
  - Verify credentials: smbreplay config show
  - Check domain name (use DOMAIN, not domain.com)
  - Ensure username has access to target share
  - Provide password: smbreplay replay <ID> --password
```

### Problem: Share not accessible
```
Error: Tree connect failed
Solution:
  - Verify share name: smbreplay config get tree_name
  - Check share exists: smbclient -L //<server> -U <user>
  - Ensure share permissions allow user access
  - Test connectivity: smbreplay validate <ID> --check-fs
```

### Problem: No sessions found after ingestion
```
Error: No SMB2 sessions found in PCAP
Solution:
  - Verify PCAP contains SMB2 traffic: tshark -r file.pcap -Y smb2
  - Check if PCAP is SMB1 (not supported)
  - Ensure PCAP is not corrupted: capinfos file.pcap
  - Try with TCP reassembly: smbreplay ingest --trace file.pcap --reassembly
```

### Problem: Replay operations fail
```
Error: Multiple operations fail during replay
Solution:
  - Run setup first: smbreplay setup <ID>
  - Check file system permissions on target
  - Verify session is compatible with target server version
  - Increase verbosity for details: smbreplay replay <ID> -vvv
  - Review specific failed operations in output
```

## Configuration Storage

```
Linux/macOS:
  ~/.config/smbreplay/config.pkl

Windows:
  %LOCALAPPDATA%\smbreplay\config.pkl

Case Directory Structure:
  ~/cases/<CASE_ID>/
    ├── traces/
    │   ├── capture1.pcap
    │   └── capture2.pcap
    └── .tracer/
        ├── capture1.pcap/
        │   ├── sessions/
        │   │   ├── smb2_session_0x01.parquet
        │   │   ├── smb2_session_0x02.parquet
        │   │   └── ...
        │   └── session_metadata.json
        └── capture2.pcap/
            └── ...
```

## Performance Tips

1. **Use --brief for quick session overview**
   - Faster than full session display
   - Good for initial analysis

2. **Filter by file to reduce noise**
   - Focus on specific files of interest
   - Reduces output clutter

3. **Use --dry-run before setup**
   - Preview changes without executing
   - Avoid unintended deletions

4. **Increase verbosity only when debugging**
   - -v for basic info
   - -vv for detailed operations
   - -vvv for full protocol debugging

5. **Use --validate before replay**
   - Catch configuration issues early
   - Saves time on failed replays

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│ Command                          │ Purpose                  │
├──────────────────────────────────┼──────────────────────────┤
│ config set <key> <value>         │ Set configuration        │
│ config show                      │ Display all settings     │
│ list traces --case <id>          │ List available PCAPs     │
│ ingest --trace <file>            │ Parse PCAP file          │
│ session --list                   │ List all sessions        │
│ session <id> --brief             │ Quick session view       │
│ session <id>                     │ Full session details     │
│ validate <id> --check-fs         │ Check replay readiness   │
│ setup <id> --dry-run             │ Preview setup changes    │
│ setup <id>                       │ Prepare file system      │
│ replay <id> --validate           │ Replay with validation   │
│ replay <id> -vvv                 │ Replay with debug output │
└──────────────────────────────────┴──────────────────────────┘
```
