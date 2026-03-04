# Skill: Root-Cause Localization for Memory Safety

## Strategy 1: ASan/Fuzzer Report Triage
When analyzing an ASan trace, do not just look at the crash line. Use this strict localization workflow:
1. **Identify the Buffer:** Which variable holds the memory? (e.g., `ctxt->input->buf`).
2. **Find the Last Mutation:** Where was this buffer last resized or reallocated? (e.g., `realloc`, `xmlBufGrow`).
3. **Check the Pointer Disconnect:** Is the pointer being dereferenced actually pointing to the *current* address of the buffer? Look for scenarios where the buffer moved to a new Heap address, but the Stack pointer still points to the old, freed Heap address.
4. **Check the Offset:** If it's an overflow, determine if the root cause is an "Off-By-One" (logic error) or a "Wrap-Around" (integer overflow).

## Strategy 2: Pointer Synchronization Audit
When a crash occurs after a buffer-modifying operation, localize the failure by auditing these patterns:

### 1. The "Stale Pointer" Origin (Use-After-Free)
Look for instances where a buffer is moved or resized, but its associated metadata (base, cur, end) is not updated atomically.
* **Detection Trap:** Code calls a growth or shrink function and subsequently calls an error handler (like `xmlFatalErr`) *before* updating `buf->cur`. If the error handler reads the stale pointer to print context, it triggers a UAF.
* **Localization Tip:** Search for `realloc` or custom growth functions. Check if `input->cur` is recalculated as an offset or if it remains a fixed, now-invalid address.


### 2. Error-Path Inconsistency & Destructive Failures
Determine if a failed memory operation destroys the "Old State" before the "New State" is fully confirmed, leaving the system in an inconsistent state.
* **Detection Trap:** A function frees `input->buffer` *before* successfully allocating `input->new_buffer`. 
* **Localization Tip:** Check if the code saves a pointer before a transition. If a function returns an error, does the parser still try to use the "new" (but failed) pointer?

### 3. Integer Overflow "Wrap-Around" Detection
Calculating buffer sizes using addition (`len + padding`) is unsafe if `len` is large, causing memory corruption before allocation even happens.
* **Detection Trap:** Look for logic like `malloc(len + 5)` or `if (len + 5 > size)`. If `len` is close to `SIZE_MAX`, `len + 5` wraps around to a small number. The allocation passes, but the subsequent write causes a heap overflow.


### 4. Order of Operations Audit
Verify if internal pointers are reset **before** or **after** a successful memory operation.
* **Observation:** If resets happen before a success check, a failure will leave the parser pointing at uninitialized memory.

## Skill: Containerized Tooling Guide
You are operating inside the vulnscan container. The project code is usually located in the default working directory (the folder you occupy upon entry), or in the subdirectory named after the project.
### Mandatory Command Prefix
Every interaction with the filesystem or build tools must use: `docker exec vulnscan [command]`

## Skill: Confidence-Weighted Reasoning Rubric
Before finalizing your analysis, evaluate your evidence:
1.  **Provenance:** Do I know which line allocated this specific memory? (+30%)
2.  **Transition:** Do I know if a `realloc` happened between allocation and crash? (+30%)
3.  **Error Handling:** Have I checked the `if (error)` path for this operation? (+20%)
4.  **Trace Consistency:** Does the code logic explain the specific sanitizer output (e.g., MSAN vs ASAN)? (+20%)

## Output Template for Turn-Based Reasoning
[THOUGHT]
... (Your analysis of the memory lifecycle and triage steps) ...
**Confidence Score:** [X]%
**Reasoning Gap:** [Specific information needed to reach 100%, e.g., "Need to find where the buffer is freed."]

## Output Template for Final Conclusion
Once your root-cause analysis is complete (Confidence Level >= 90%), your absolute final output must be a single JSON code block. Do not include conversational filler after the JSON block.

The JSON must strictly adhere to this schema to allow for automated extraction:

```json
{
  "status": "LOCALIZED",
  "vulnerabilities": [
    {
      "file": "path/to/file.c",
      "method": "name_of_vulnerable_function",
      "lines": [
        "1354",
        "1358-1360"
      ],
      "confidence_score": 95,
      "root_cause_summary": "A concise, 1-2 sentence technical explanation of the state-sync failure or math flaw."
    }
  ]
}