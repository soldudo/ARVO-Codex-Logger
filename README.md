# ARVO-Codex-Logger
Logger to record Codex attempts to identify and patch vulnerabilities from the ARVO database.

## Prototype
This manually operated prototype uses several lists which must be manually updated to match the selection of arvo vulnerabilities
- vuln_list contains arvo vulnerability id numbers
- project_list contains respective arvo vulnerability project name
- fuzz_target contains the fuzzer used for the respective vulnerability 
- crash_list contains the crash type of each respective vulnerability
- workspace_list contains the directory of the vulnerable projects in the copied arvo container filetrees
- experiment_no switch to specify the vulnerability to be tested on this run
- prompt#_fail optional hard-coded prompts to use when the first first patch attempt is unsuccessful. Used to provide additional context to Codex for a second attempt. Note: in the continuous implementation this is primarily used when a session is interrupted and must be resumed using the alternative resume command. In an uninterrupted continuous session the user can provide subsequent prompts from the command line.

## Logs
Logs are saved in the runs directory.
- A subdirectory is created for each run using the vulnerability # and timestamp.
- These directories can be used to store patched files or subsequent crash logs to store additional artifacts of each run.

## Preparation - ARVO containers
Extract the filesystem of the vulnerable arvo container
- Execute these commands from ARVO-Codex-Logger directory
- docker create --name arvo-42488087-vul n132/arvo:42488087-vul
- docker export arvo-42488087-vul -o 42488087-vul.tar
-	mkdir arvo-42488087-vul
-	tar -xf 42488087-vul.tar -C arvo-42488087-vul
-	Errors such as these are expected and safe to ignore:
  <img width="864" height="338" alt="image" src="https://github.com/user-attachments/assets/197e8bb3-a2cb-4607-9b6b-2202e23ae455" /><br>
Navigate to this new directory and generate the crash output:
- 	./out/fuzzer-wolfssl-server-randomize tmp/poc 2> crash_report.log

## Instructions 
- Populate vuln_list with a subset of vulnerabilities to perform the experiment with.
- Ensure the other lists are populated according to their descriptions above. They must all be in the same order in this version.
- Set experiment_no to choose which vulnerability is to be tested on this run.
- run arvo_codex_manual.py
- monitor command line for Codex actions and reasoning.
- Codex may prompt for additional information.
- Once Codex attempts a patch, review the patch details in the command line, the json log file, or navigate to the project directory and review changed files.
- Ensure the patch was applied, or apply the code changes manually.
- Rerun the poc with the fuzzer (./out/fuzzer-wolfssl-server-randomize tmp/poc 2> crash_report2.log)

