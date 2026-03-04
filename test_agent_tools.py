import logging
import subprocess
import sys
import agent_tools


logging.basicConfig(level=logging.INFO, stream=sys.stdout)

container_name = 'inject_test'

def test_get_model(container_name: str):
    model = agent_tools.get_model(container_name)

    print(f'Model output: {model}')
    assert model is not None

# def test_data_object():

# test_get_model(container_name)

def test_pwd(container_name: str):
    pwd_cmd = ['docker', 'exec', container_name, 'pwd']
    try:
        result = subprocess.run(pwd_cmd, capture_output=True, text=True)
        workspace_relative = result.stdout.strip()
        return workspace_relative
    except subprocess.CalledProcessError as e:
        print(f'container {container_name} pwd failed: {e}')

print(test_pwd(container_name))

def test_conduct_run(vuln_id=424242614, )