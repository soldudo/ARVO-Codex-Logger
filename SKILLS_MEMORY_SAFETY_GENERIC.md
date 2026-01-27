# AGENT SKILLS: MEMORY SAFETY & FUZZING ANALYSIS

## 1. Skill Capabilities
**Core Competency:** Low-level memory management, C/C++ security analysis, and interpretation of dynamic analysis tools (Fuzzers/ASan).
**Primary Function:** To analyze crash artifacts (stack traces, ASan reports, core dumps) and patch memory safety violations (buffer overflows, use-after-free, etc.) without breaking binary compatibility.

---

## 2. Vulnerability Detection Patterns

### 🔍 Spatial Safety (Bounds Violations)
* **Stack/Heap Buffer Overflow:**
    * *Trigger:* Writing data past the allocated boundaries of a stack variable or heap chunk.
    * *ASan Signature:* `stack-buffer-overflow` or `heap-buffer-overflow` on `WRITE` / `READ`.
    * *Root Cause:* Off-by-one errors, missing null-terminators, or using unbounded functions like `strcpy`, `strcat`, `sprintf`, `gets`.
* **Global Buffer Overflow:**
    * *Trigger:* Accessing global/static arrays with an unchecked index.
    * *ASan Signature:* `global-buffer-overflow`.

### 🔍 Temporal Safety (Pointer Lifecycle)
* **Use-After-Free (UAF):**
    * *Trigger:* Dereferencing a pointer after the memory it points to has been `free()`d.
    * *ASan Signature:* `heap-use-after-free` (Look for "freed by thread X here" vs "previously allocated here").
    * *Root Cause:* Dangling pointers, race conditions in multi-threaded cleanup, or confusion over object ownership.
* **Double Free:**
    * *Trigger:* Calling `free()` on the same address twice.
    * *ASan Signature:* `attempting double-free`.
    * *Risk:* Heap corruption leading to arbitrary code execution.

### 🔍 Initialization & Types
* **Uninitialized Memory Read:**
    * *Trigger:* Branching or indexing based on "garbage" stack values.
    * *Tool Output:* MemorySanitizer (MSan) reports `use-of-uninitialized-value`.
* **Integer Overflow/Underflow:**
    * *Trigger:* Arithmetic wrapping that leads to small allocation sizes (e.g., `malloc(num_elements * size)` wrapping to a small number).
    * *Result:* Subsequent buffer overflow when data is copied into the too-small buffer.

---

## 3. Remediation Toolset & Strategies

### 🛠️ Safe Coding Practices (C/C++)
* **Bounds Checking:**
    * Replace `strcpy`/`strcat` with `strncpy`/`strncat` (careful with null-termination) or `strlcpy`/`strlcat`.
    * Use `snprintf` instead of `sprintf`.
* **Pointer Hygiene:**
    * **Nullify after Free:** Immediately set pointers to `NULL` (or `nullptr`) after freeing.
      ```c
      free(ptr);
      ptr = NULL; // Prevents UAF and Double Free
      ```
* **Modern C++ (RAII):**
    * Replace raw pointers (`*`) with Smart Pointers (`std::unique_ptr`, `std::shared_ptr`) to automate lifecycle management.
    * Use `std::vector` or `std::string` instead of raw C-arrays.

### 🛠️ Analyzing ASan Reports
1.  **Shadow Bytes:** Decode the ASan shadow map to pinpoint the offset.
    * `fa`: Heap Left Redzone (Underflow)
    * `fd`: Heap Right Redzone (Overflow)
    * `fd`: Freed Heap Region (Use-After-Free)
2.  **Stack Trace Correlation:** Match the `SCARINESS` score and stack frames to the source code line numbers.

---

## 4. Verification Strategies

### ✅ Static Analysis Checks
* [ ] Are loop conditions strictly bounded by buffer size, not input size?
* [ ] Is `sizeof()` applied correctly (e.g., `sizeof(int*)` vs `sizeof(int)`)?
* [ ] Are integer overflows checked before using values in `malloc`?

### ✅ Dynamic Test Cases (Reproduction)
* **Fuzzer Reproduction:** Isolate the crash input (e.g., `id:000001,sig:11,src:000000,op:havoc,rep:16`).
* **Sanitizer Run:** Compile the fix with `-fsanitize=address,undefined -g`. Run the reproduction input.
    * **Success:** Program handles input (error message or clean exit) without ASan aborting.
    * **Failure:** ASan reports a new error or the same error.

---

## 5. Memory Safety Decision Matrix

| ASan/Fuzzer Error | Likely Root Cause | Recommended Action |
| :--- | :--- | :--- |
| **heap-buffer-overflow** | Writing beyond `malloc` size. | Verify allocation math; switch to `std::vector` or check bounds before write. |
| **stack-buffer-overflow** | Unbounded write to local array. | Increase buffer size or move to heap; enforce strict input length limits. |
| **stack-use-after-return** | Returning address of local var. | **Never** return `&local_var`. Allocate on heap or pass by reference. |
| **SEGV on unknown address** | NULL pointer dereference. | Add `if (ptr == NULL)` checks before access. |
| **Integer Overflow** | Math wraps around (MaxInt+1). | Use `__builtin_add_overflow` or checks like `if (a > MAX - b)`. |