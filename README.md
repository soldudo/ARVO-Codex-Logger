# CARO: Code agent ARVO experiment Orchestration

**CARO** is an assistant that dutifully documents automated agentic ARVO vulnerability patching experiments like a "well-trained puppy."

Named after astronomer pioneer Caroline Herschel known for keeping meticulous records of astronomical observations, it orchestrates the entire experiment lifecycle and its duties include:
* Retrieve vulnerability context from ARVO database
* Manage Docker container CRUD operations and tidy up
* Invokes AI agents and catalogs session data including execution logs, reasoning and token usage.
* Collects experiment artifacts for analysis & reproducability.
* Re-compiles ARVO containers with agent's patched code and records the output from re-fuzzing the poc.

## Experiment Workflow

* **Automated Experiment Prep**: Fetches project metadata and crash types directly from `arvo.db`, pulls the related ARVO Docker container, generates a fresh crash log, and extracts the source code to the agent's local workspace.
* **Agent Orchestration**: Runs the Codex agent in `--full-auto` mode with a prompt that includes the actual crash log and file system context.
* **Patch Verification**:
    1.  Identifies files modified by the agent.
    2.  Spins up a standby container.
    3.  Injects the AI-generated patches.
    4.  Triggers recompilation (`arvo compile`).
    5.  Re-runs the Proof of Concept (POC) to evaluate whether the patch resolved the crash.
* **Artifact Archiving**: Automatically saves agent logs, original file versions, patched file versions, and the results of re-running the poc on the patched and re-compiled container.

## Prerequisites

* **Python 3.x**
* **Docker Engine**: Must be running and accessible by the script (the script runs `docker` commands directly).
* **Codex CLI**: The `codex` command must be in your system PATH. Requires login to ChatGPT Plus/Pro/Business accouunt.
* **arvo.db**: A SQLite database in the root directory containing the `arvo` table with columns: `localId`, `project`, and `crash_type`.

## Configuration

Set the ARVO vulnerability ID the experiment will be conducted on via **`experiment_setup.json`** in the project root. 

```json
{
    "arvo_id": 42538667,
    "initial_prompt": true
}
```
Note: Only the initial prompt setting is currently supported. To run a second attempt, calls to codex exec, prompts, and crash_log variables must be manually configured. See code comments for examples. 

## To Conduct Experiment

After setting an **'arvo_id'** in the **'experiment_setup.json'** run caroline.py

## Logs

The agent's session will be documented in **'runs/arvo-vuln_ID-timestamp/'** along with artifacts (files & crash logs).

View caroline.log to debug any issues.

## TODO

* **Export Quantitative Data** Export duration, tokens and timestamps to dataframe or modified database.
* **Second-try Workflow** Add logic to conduct a second attempt using the resume flag, and additional context such as the patched container's crash log and filenames, line numbers and function names from ground truch patch diff.
* **Multi-Agent Support** Implement connection and altered workflow for other agents. Current candidate: Claude Code
