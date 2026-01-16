import pytest
from unittest.mock import MagicMock, patch
from arvo_tools import refuzz

@patch('arvo_tools.run_command')
def test_refuzz(mock_run_command):

