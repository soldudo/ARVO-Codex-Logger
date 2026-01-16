from experiments import update_setup_file, run_experiment_list
import json
import pytest
from unittest.mock import patch, call

@pytest.fixture
def setup_file(tmp_path):
    f = tmp_path / "experiment_setup.json"
    initial_data = {"arvo_id": 419085594, "initial_prompt": True}
    f.write_text(json.dumps(initial_data))
    return f

@patch('experiments.subprocess.run')
def test_experiment_run(mock_run, setup_file):

    test_experiment_list = [
        396958483,
        370032378,
    ]
    setup_path = str(setup_file)

    run_experiment_list(test_experiment_list, setup_path)

    assert mock_run.call_count == len(test_experiment_list)

    expected_call = call(['python', 'caro.py'])
    mock_run.assert_has_calls([expected_call] * len(test_experiment_list))

    with open (setup_path, 'r') as f:
        final_data = json.load(f)
    
    assert final_data['arvo_id'] == test_experiment_list[-1]
