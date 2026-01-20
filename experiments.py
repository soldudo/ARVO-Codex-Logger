import json
import subprocess

setup_path = "experiment_setup.json"

experiment_list = [
    # 42534486,
    # 42528951,
    42531212,
    42531502,
    437162340,
    419085594

]

run_list = [
    'arvo-42531212-vul-1768028264',
    'arvo-42531502-vul-1768027428',
    'arvo-437162340-vul-1768025936',
    'arvo-419085594-vul-1767938596'

]

context_list = [
    'A known correct fix made changes to the file: parserInternals.c in the function xmlSwitchInputEncoding around lines 1354, 1356, and 1365-1369.',
    'A known correct fix made changes to the files: examples/pem/pem.c at lines 297 and 298, src/ssl.c around lines 5613, 9951, 10284, 10530, 11739-11742, 23154, 24532, 24549 and 24773, and 28313, src/wolfio.c around line 1412, tests/api.c around lines 4708, 25742, 28154-28157, 28769, 29683, 31029-31030, 31222, 31629, 31953, 32116, 32462, 32833, 33345, 33420, and 62378, wolfcrypt/src/asn.c around lines 12950, 26983-26984, 27761, 35076, wolfcrypt/src/pkcs7.c around lines 4283-4284, and wolfcrypt/test/test.c around line 33009.',
    'A known correct fix made changes to the file: src/lib/ndpi_utils.c at line 3240.',
    'A known correct fix made changes to the file: sapi/fuzzer/fuzzer-sapi.c at line 48'
]


def update_setup_file(arvo_id: int, run_id: str, context: str, setup_path: str) -> None:
    try:
        with open(setup_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Experiment Setup file {setup_path} not found.")
    data['arvo_id'] = arvo_id
    data['run_id'] = run_id
    data['additional_context'] = context
    with open(setup_path, 'w') as f:
        json.dump(data, f)


def run_experiment_list(experiments: list[int], runs: list[str], contexts: list[str], setup_path: str) -> None:
    for arvo_id, run_id, context in zip(experiments, runs, contexts): 
        update_setup_file(arvo_id, run_id, context, setup_path)
        try:
            subprocess.run(['python', 'caro.py'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: caro.py failed for experiment {arvo_id}.")
        except Exception as e:
            print(f"An unexpected error occurred for experiment {arvo_id}: {e}")


if __name__ == "__main__":
    run_experiment_list(experiment_list, run_list, context_list, setup_path)

        
