# Skill: Confidence-Weighted Reasoning

## Objective
To prevent "hallucinated fixes" by forcing an explicit audit of the evidence gathered.

## Confidence Rubric
Before finalizing a [THOUGHT] block, ask yourself:
1.  **Provenance:** Do I know exactly which line allocated the memory currently being dereferenced? (+30%)
2.  **Transition:** Do I know if a `realloc` or encoding switch happened between allocation and crash? (+30%)
3.  **Error Handling:** Have I checked what happens to these pointers if the memory operation fails? (+20%)
4.  **Local Reproduction:** Have I seen the variable values in the trace or code logic that confirm this path? (+20%)

## Output Format
[THOUGHT]
... (Your analysis) ...
**Confidence Score:** [X]%
**Reasoning Gap:** [What piece of information is missing to reach 100%?]

# Skill: Root-Cause Localization for Memory Safety

## Strategy: Pointer Synchronization Audit
When a crash occurs after a buffer-modifying operation (like an encoding switch or growth), audit the code for these three flaws:

### 1. The "Stale Pointer" Pattern
Check if the code updates the buffer but fails to update the cursors.
* **Vulnerable:** `buffer = realloc(buffer, new_size); // input->cur still points to old address`
* **Fix:** Ensure `input->base`, `input->cur`, and `input->end` are recalculated immediately after reallocation.

### 2. Error-Path Inconsistency
Ensure that if a memory operation fails, the system rolls back to a safe state.
* **Strategy:** Save the original pointer to a temporary variable. If the modification function returns an error, restore the original pointer instead of leaving it pointing to a "moved" or "freed" location.



### 3. Order of Operations (Atomic Resets)
Verify the sequence of "Reset" vs. "Check."
* **Incorrect:** Reset pointers $\rightarrow$ Perform operation $\rightarrow$ Check for error. (The state is corrupted if the operation fails).
* **Correct:** Perform operation $\rightarrow$ Check for error $\rightarrow$ **Only then** reset pointers.

## Tooling & Command Patterns

### Mapping Buffer Usage
Use `rg` to find every location where a buffer's metadata is modified:
```bash
# Find where the 'cur' pointer is manually adjusted
rg "input->cur\s*=" 

# Find where the buffer is resized
rg "xmlBufGrow|realloc|xmlBufAdd"
```

## Contextual Inspection
When inspecting a function like xmlSwitchInputEncoding, always look 50 lines before and after to see how variables are saved before the "danger zone":

`sed -n '1300,1400p' parserInternals.c`

## Validation Checklist
[ ] Does the fix prevent the crash?

[ ] Does the fix maintain the original data if a memory allocation fails?

[ ] Have I avoided adding a "silencing" guard clause that just hides a deeper corruption?