import os
import pytest
import pandas as pd
from smbreplay import ingestion

# Test configuration
CASE_NUMBER = "2009420420"
TRACE_NAME = "scoa_replay_freshvol"
TRACES_FOLDER = os.environ.get("TRACES_FOLDER", os.path.expanduser("~/cases"))
CAPTURE_PATH = os.path.join(TRACES_FOLDER, CASE_NUMBER, f"{TRACE_NAME}.pcapng")

def test_run_ingestion_and_load():
    # Skip test if the specific test file doesn't exist
    if not os.path.exists(CAPTURE_PATH):
        pytest.skip(f"Test file not found: {CAPTURE_PATH}")

    # Run ingestion
    result = ingestion.run_ingestion(
        capture_path=CAPTURE_PATH,
        reassembly_enabled=False,
        force_reingest=True,
        verbose=True
    )
    assert result is not None, "Ingestion failed, result is None"
    assert "full_df" in result and isinstance(result["full_df"], pd.DataFrame)
    assert not result["full_df"].empty, "Ingested DataFrame is empty"
    assert "sessions" in result and isinstance(result["sessions"], dict)
    assert len(result["sessions"]) > 0, "No sessions extracted"

    # Print lock frames after ingestion
    print("\n--- Frame 32 after ingestion ---")
    print(result["full_df"][result["full_df"]["frame.number"] == 32])
    print("\n--- Frame 44 after ingestion ---")
    print(result["full_df"][result["full_df"]["frame.number"] == 44])


    # Save and reload
    loaded = ingestion.load_ingested_data(CASE_NUMBER, TRACE_NAME)
    assert loaded is not None, "Failed to load ingested data"
    assert "full_df" in loaded and isinstance(loaded["full_df"], pd.DataFrame)
    assert not loaded["full_df"].empty, "Loaded DataFrame is empty"
    assert "sessions" in loaded and isinstance(loaded["sessions"], dict)
    assert len(loaded["sessions"]) > 0, "No sessions loaded"
    assert "metadata" in loaded

    # Print lock frames after reload
    print("\n--- Frame 32 after reload ---")
    print(loaded["full_df"][loaded["full_df"]["frame.number"] == 32])
    print("\n--- Frame 44 after reload ---")
    print(loaded["full_df"][loaded["full_df"]["frame.number"] == 44])

    # Validate
    assert ingestion.validate_ingested_data(loaded), "Validation failed for loaded data"
