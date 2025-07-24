import pandas as pd
import pytest
from smbreplay.ingestion import (
    normalize_sesid_vectorized,
    normalize_cmd_vectorized,
    extract_unique_sessions_optimized,
)

def test_normalize_sesid_vectorized_basic():
    series = pd.Series([
        '0x1234567890abcdef',
        '0x0000000000000000',
        '0x1111111111111111,0x2222222222222222',
        '',
        None,
        '0x3333333333333333,0x0000000000000000,0x4444444444444444',
    ])
    result = normalize_sesid_vectorized(series)
    assert result.iloc[0] == {'0x1234567890abcdef'}
    assert result.iloc[1] == set()
    assert result.iloc[2] == {'0x1111111111111111', '0x2222222222222222'}
    assert result.iloc[3] == set()
    assert result.iloc[4] == set()
    assert result.iloc[5] == {'0x3333333333333333', '0x4444444444444444'}

def test_normalize_cmd_vectorized_basic():
    series = pd.Series([
        '3',
        '5,6',
        '',
        None,
        '7,8',
    ])
    result = normalize_cmd_vectorized(series)
    assert result.iloc[0] == {'3'}
    assert result.iloc[1] == {'5', '6'}
    assert result.iloc[2] == set()
    assert result.iloc[3] == set()
    assert result.iloc[4] == {'7', '8'}

def test_extract_unique_sessions_optimized():
    df = pd.DataFrame({
        'smb2.sesid': [
            '0x1234567890abcdef',
            '0x0000000000000000',
            '0x1111111111111111,0x2222222222222222',
            '',
            None,
            '0x3333333333333333,0x0000000000000000,0x4444444444444444',
        ]
    })
    unique = extract_unique_sessions_optimized(df)
    assert unique == [
        '0x1234567890abcdef',
        '0x1111111111111111',
        '0x2222222222222222',
        '0x3333333333333333',
        '0x4444444444444444',
    ] 