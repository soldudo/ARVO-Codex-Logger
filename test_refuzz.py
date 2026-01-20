import logging
import sys
from arvo_tools import refuzz

logging.basicConfig(level=logging.INFO, stream=sys.stdout)

target_container = "arvo-424242614-vul-1767236265"
# target_container = "arvo-420638555-vul-1767424534-patch" # test timeout

print(f"--- Testing refuzz on {target_container} ---")

try:
    result = refuzz(target_container)
    
    print("\n[RESULT]")
    print(f"Return Code: {result.returncode}")
    print(f"Stdout: {result.stdout}")
    print(f"Stderr: {result.stderr}")

except Exception as e:
    print(f"Test Failed: {e}")