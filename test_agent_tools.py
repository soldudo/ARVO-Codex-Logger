import logging
import sys
import agent_tools


logging.basicConfig(level=logging.INFO, stream=sys.stdout)

def test_get_model():
    model = agent_tools.get_model()

    print(f'Model output: {model}')
    assert model is not None

def test_data_object():
