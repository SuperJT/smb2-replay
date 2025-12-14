from unittest.mock import MagicMock, patch

from smbreplay.constants import FILE_INFO_CLASSES
from smbreplay.handlers import query_directory


def make_file_open_mock():
    m = MagicMock()
    m.query_directory_info.return_value = ["dir_info"]
    m.query_full_directory_info.return_value = ["full_dir_info"]
    m.query_both_directory_info.return_value = ["both_dir_info"]
    m.query_names_info.return_value = ["names_info"]
    m.query_id_both_directory_info.return_value = ["id_both_dir_info"]
    m.query_id_full_directory_info.return_value = ["id_full_dir_info"]
    m.query_directory.return_value = ["generic_dir_info"]
    return m


def test_query_directory_info_file_directory_information():
    file_open = make_file_open_mock()
    result = query_directory._query_directory_info(
        file_open,
        FILE_INFO_CLASSES["FILE_DIRECTORY_INFORMATION"],
        "*",
        1024,
        restart_scan=True,
        return_single_entry=True,
        file_index=5,
    )
    assert result == ["dir_info"]
    file_open.query_directory_info.assert_called_once()


def test_query_directory_info_file_full_directory_information():
    file_open = make_file_open_mock()
    result = query_directory._query_directory_info(
        file_open,
        FILE_INFO_CLASSES["FILE_FULL_DIRECTORY_INFORMATION"],
        "*",
        1024,
    )
    assert result == ["full_dir_info"]
    file_open.query_full_directory_info.assert_called_once()


def test_query_directory_info_file_both_directory_information():
    file_open = make_file_open_mock()
    result = query_directory._query_directory_info(
        file_open,
        FILE_INFO_CLASSES["FILE_BOTH_DIRECTORY_INFORMATION"],
        "*",
        1024,
    )
    assert result == ["both_dir_info"]
    file_open.query_both_directory_info.assert_called_once()


def test_query_directory_info_filenames_information():
    file_open = make_file_open_mock()
    result = query_directory._query_directory_info(
        file_open,
        FILE_INFO_CLASSES["FILENAMES_INFORMATION"],
        "*",
        1024,
    )
    assert result == ["names_info"]
    file_open.query_names_info.assert_called_once()


def test_query_directory_info_fileid_both_directory_information():
    file_open = make_file_open_mock()
    result = query_directory._query_directory_info(
        file_open,
        FILE_INFO_CLASSES["FILEID_BOTH_DIRECTORY_INFORMATION"],
        "*",
        1024,
    )
    assert result == ["id_both_dir_info"]
    file_open.query_id_both_directory_info.assert_called_once()


def test_query_directory_info_fileid_full_directory_information():
    file_open = make_file_open_mock()
    result = query_directory._query_directory_info(
        file_open,
        FILE_INFO_CLASSES["FILEID_FULL_DIRECTORY_INFORMATION"],
        "*",
        1024,
    )
    assert result == ["id_full_dir_info"]
    file_open.query_id_full_directory_info.assert_called_once()


def test_query_directory_info_unsupported_class():
    file_open = make_file_open_mock()
    result = query_directory._query_directory_info(
        file_open,
        999,  # unsupported class
        "*",
        1024,
    )
    assert result == ["generic_dir_info"]
    file_open.query_directory.assert_called_once()


def test_query_directory_info_smb_exception():
    file_open = make_file_open_mock()
    # Patch SMBException in the handler's namespace
    with patch("smbreplay.handlers.query_directory.SMBException", Exception):
        file_open.query_directory_info.side_effect = Exception("SMB error")
        result = query_directory._query_directory_info(
            file_open,
            FILE_INFO_CLASSES["FILE_DIRECTORY_INFORMATION"],
            "*",
            1024,
        )
        assert result is None
