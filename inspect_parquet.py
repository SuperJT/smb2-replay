#!/usr/bin/env python3
"""
Simple script to inspect parquet schema and check for file size fields.
Run inside container with direct parquet access.
"""

import sys

# Check if we have pyarrow
try:
    import pyarrow.parquet as pq
    print("✓ pyarrow available\n")
except ImportError:
    print("✗ pyarrow not available")
    sys.exit(1)

# Check if we have pandas
try:
    import pandas as pd
    print("✓ pandas available\n")
except ImportError:
    print("✗ pandas not available")
    sys.exit(1)

if len(sys.argv) < 2:
    print("Usage: python inspect_parquet.py <parquet_file_path>")
    print("Example: python inspect_parquet.py /path/to/session.parquet")
    sys.exit(1)

parquet_file = sys.argv[1]
print(f"Inspecting: {parquet_file}\n")
print("="*80)

try:
    # Read the parquet file
    table = pq.read_table(parquet_file)
    df = table.to_pandas()
    
    print(f"✓ Loaded parquet file")
    print(f"  Rows: {len(df)}")
    print(f"  Columns: {len(df.columns)}\n")
    
    # Show all column names
    print("="*80)
    print("ALL COLUMNS:")
    print("="*80)
    for idx, col in enumerate(df.columns, 1):
        print(f"{idx:3d}. {col}")
    
    # Check for file size related columns
    print("\n" + "="*80)
    print("FILE SIZE RELATED COLUMNS:")
    print("="*80)
    size_cols = [col for col in df.columns if 'eof' in col.lower() or 'alloc' in col.lower() or 'size' in col.lower()]
    if size_cols:
        for col in size_cols:
            non_null = df[col].notna().sum()
            print(f"  {col}: {non_null} non-null values")
            if non_null > 0:
                sample_values = df[df[col].notna()][col].head(3).tolist()
                print(f"    Sample values: {sample_values}")
    else:
        print("  ✗ No file size related columns found!")
    
    # Check for CREATE responses (cmd=5)
    print("\n" + "="*80)
    print("CREATE RESPONSES (cmd=5):")
    print("="*80)
    if 'smb2.cmd' in df.columns:
        create_ops = df[df['smb2.cmd'] == '5']
        print(f"  Found {len(create_ops)} CREATE operations")
        
        if len(create_ops) > 0:
            print("\n  First CREATE operation columns with values:")
            first_create = create_ops.iloc[0]
            for col in first_create.index:
                if pd.notna(first_create[col]) and first_create[col] != '':
                    val_str = str(first_create[col])
                    if len(val_str) > 100:
                        val_str = val_str[:100] + "..."
                    print(f"    {col}: {val_str}")
    else:
        print("  ✗ No smb2.cmd column found!")
    
    # Check for SET_INFO operations (cmd=17)
    print("\n" + "="*80)
    print("SET_INFO OPERATIONS (cmd=17):")
    print("="*80)
    if 'smb2.cmd' in df.columns:
        setinfo_ops = df[df['smb2.cmd'] == '17']
        print(f"  Found {len(setinfo_ops)} SET_INFO operations")
        
        if len(setinfo_ops) > 0:
            print("\n  First SET_INFO operation columns with values:")
            first_setinfo = setinfo_ops.iloc[0]
            for col in first_setinfo.index:
                if pd.notna(first_setinfo[col]) and first_setinfo[col] != '':
                    val_str = str(first_setinfo[col])
                    if len(val_str) > 100:
                        val_str = val_str[:100] + "..."
                    print(f"    {col}: {val_str}")
    else:
        print("  ✗ No smb2.cmd column found!")
    
    print("\n" + "="*80)
    print("INSPECTION COMPLETE")
    print("="*80)
    
except Exception as e:
    print(f"\n✗ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
