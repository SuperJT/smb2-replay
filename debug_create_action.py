#!/usr/bin/env python3
"""
Debug script to test create.action field mapping and normalization.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'smbreplay_package'))

from smbreplay.constants import normalize_hex_field, CREATE_ACTION_DESC, FIELD_MAPPINGS
import pandas as pd

def test_create_action_mapping():
    """Test the create.action field mapping and normalization."""
    print("Testing create.action field mapping and normalization")
    print("=" * 60)
    
    # Test the normalization function
    print("1. Testing normalize_hex_field for smb2.create.action:")
    test_values = [1, "1", "0x1", "0x01", "1,2", None, "", "N/A"]
    
    for value in test_values:
        normalized = normalize_hex_field(value, "smb2.create.action")
        print(f"   Input: {repr(value)} -> Normalized: {repr(normalized)}")
    
    print("\n2. Testing CREATE_ACTION_DESC mapping:")
    for k, v in CREATE_ACTION_DESC.items():
        print(f"   {k} -> {v}")
    
    print("\n3. Testing FIELD_MAPPINGS['smb2.create.action']:")
    mapping = FIELD_MAPPINGS["smb2.create.action"]["mapping"]
    normalize = FIELD_MAPPINGS["smb2.create.action"]["normalize"]
    
    print(f"   Mapping: {mapping}")
    
    # Test the mapping with normalized values
    print("\n4. Testing mapping with normalized values:")
    for value in [1, "1", "0x1", "0x01"]:
        normalized = normalize(value)
        mapped = mapping.get(str(normalized), "NOT_FOUND")
        print(f"   Input: {repr(value)} -> Normalized: {repr(normalized)} -> Mapped: {mapped}")
    
    # Test with pandas apply
    print("\n5. Testing with pandas apply (like in session_manager):")
    test_df = pd.DataFrame({
        'smb2.create.action': [1, "1", "0x1", "0x01", None, "", "N/A"]
    })
    
    print("   Original DataFrame:")
    print(test_df)
    
    # Apply normalization
    test_df['smb2.create.action'] = test_df['smb2.create.action'].apply(normalize)
    print("\n   After normalization:")
    print(test_df)
    
    # Apply mapping
    test_df['smb2.create.action_desc'] = test_df['smb2.create.action'].apply(
        lambda x: mapping.get(str(x), "") if pd.notna(x) and str(x).strip() != "" and str(x) != "None" else ""
    )
    print("\n   After mapping:")
    print(test_df)

if __name__ == "__main__":
    test_create_action_mapping() 