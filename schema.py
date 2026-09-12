from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

class RunMode(Enum):
    LOC = 'loc'
    PATCH = 'patch'
    TEST = 'test'


# --- DDL ---------------------------------------------------------------------
# Defined here so patch_verification_upgrade.py and run_parser.init_db() share
# one source of truth. patch_data drifted between those two once already
# (compile_errors arrived inline in one and via ALTER in the other).

# One row per verification attempt of a run_mode='patch' run. patch_data stays
# as a denormalised view of the newest attempt so the analysis/ scripts that
# read it keep working unchanged.
PATCH_VERIFICATION_DDL = '''
CREATE TABLE IF NOT EXISTS patch_verification (
    verification_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    attempt           INTEGER NOT NULL,

    -- provenance
    started_at        TEXT,
    finished_at       TEXT,
    applier_sha256    TEXT,      -- sha256 of diff_tools.py as executed
    image_tag         TEXT,
    container_workdir TEXT,

    -- stage 1: baseline POC output
    baseline_source   TEXT,      -- 'arvo.crash_output' | 'live'
    baseline_log      TEXT,

    -- stage 2: patch application (aggregated over entries)
    patch_text        TEXT,      -- exact bytes fed to the applier
    patch_sha256      TEXT,
    patch_recounted   INTEGER,   -- hunk headers this run rewrote
    patch_strip       INTEGER,   -- denormalised out of patch_argv
    patch_argv        TEXT,      -- JSON; only durable record of the flags
    patch_rc          INTEGER,   -- worst rc across entries
    patch_stdout      TEXT,      -- all entries, with per-entry markers
    patch_stderr      TEXT,
    patch_hunks_ok    INTEGER,
    patch_hunks_failed INTEGER,
    patch_max_fuzz    INTEGER,

    -- stage 3: recompile (streams merged; see diff_tools.stream_compile)
    compile_rc        INTEGER,
    compile_output_extract TEXT,
    compile_log_path  TEXT,
    compile_log_bytes INTEGER,
    compile_duration_s REAL,
    compile_timed_out INTEGER,

    -- baseline + patch + patched POC, assembled for the LLM pass
    transcript_path   TEXT,

    -- stage 4: patched POC
    poc_rc            INTEGER,
    poc_stdout        TEXT,
    poc_stderr        TEXT,
    poc_duration_s    REAL,
    poc_timed_out     INTEGER,

    -- adjudication
    is_crash_resolved BOOLEAN,
    adjudicated_by    TEXT,
    adjudicated_at    TEXT,
    adjudication_note TEXT,

    -- reserved for the downstream LLM pass; NULL until it runs
    compile_verified  INTEGER,
    compile_verdict_note TEXT,

    UNIQUE (run_id, attempt)
)
'''

PATCH_VERIFICATION_INDEX_DDL = '''
CREATE INDEX IF NOT EXISTS idx_patch_verification_run
    ON patch_verification(run_id)
'''

@dataclass
class RunParams:
    vuln_id: int
    run_id: str
    agent: str
    run_mode: str
    loc_run_id: str
    prompt: str
    is_resume: bool = False
    resume_session_id: Optional[str] = None


# Classes below are legacy from first implementation (codex patching runs)
class ContentType(Enum):
    ORIGINAL = "original"
    PATCHED = "patched"
    GROUND_TRUTH = "ground_truth"

class CrashLogType(Enum):
    ORIGINAL = "original"
    PATCH = "patch"

# dataclass object definitions

@dataclass
class LegacyRunRecord:
    run_id: str
    vuln_id: int

    workspace_relative: str
    patch_url: str
    prompt: str

    duration: float
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    total_tokens: int

    agent: str
    agent_model: str
    resume_flag: bool
    resume_id: str
    agent_log: str
    agent_reasoning: str
    modified_files: List[str] = field(default_factory=list)