# AGENT SKILLS: MEMORY SAFETY REMEDIATION

## 1. Core Competency: Pointer Synchronization
**Context:** In C/C++, `realloc` invalidates all pointers referencing the old memory block.
**Rule:** NEVER assume a pointer (`input->cur`, `base`, `ptr`) is valid after a buffer growth or shrinkage operation unless it has been explicitly updated.

### 🚩 The "Stale Pointer" Pattern (Use-After-Free)
* **Detection:** Code calls `grow(buf)` or `shrink(buf)` and subsequently calls an error handler or continues processing without updating `buf->cur`.
* **The Trap:** Error handlers (like `xmlFatalErr`) often print context. If they read `input->cur` *after* a failed realloc but *before* the pointer update, it causes a UAF.
* **The Fix:**
    1.  **Update Immediately:** Call the update function (e.g., `xmlBufUpdateInput`) immediately after realloc, *even if* the realloc logic failed or returned an error code.
    2.  **Order of Operations:** Ensure `reset` logic happens before `error_reporting` logic.

## 2. Core Competency: Transactional State Management
**Context:** Complex operations (encoding switches, format parsing) often fail halfway through.
**Rule:** Do not destroy the "Old State" until the "New State" is fully confirmed and valid.

### 🚩 The "Destructive Failure" Pattern
* **Detection:** A function frees `input->buffer` *before* successfully allocating `input->new_buffer`.
* **The Fix:**
    ```c
    // 1. Save old state
    old_buf = input->buffer;
    // 2. Attempt operation
    if (allocate_new() < 0) {
        // 3. Rollback on failure (crucial!)
        input->buffer = old_buf;
        return ERROR;
    }
    // 4. Commit success
    free(old_buf);
    ```

## 3. Core Competency: Integer Overflow Prevention
**Context:** Calculating buffer sizes using addition (`len + padding`) is unsafe if `len` is large.
**Rule:** Check for overflow *before* allocation, do not rely on the allocator to catch it.

### 🚩 The "Wrap-Around" Pattern
* **Detection:** `malloc(len + 5)` or `if (len + 5 > size)`.
* **The Risk:** If `len` is close to `SIZE_MAX`, `len + 5` wraps to `4`. The check passes (`4 < size`), but the write causes a heap overflow.
* **The Fix:** Use subtraction for checks.
    * *Bad:* `if (len + needed > size)`
    * *Good:* `if (size - needed < len)` (Precondition: ensure `size > needed`)

## 4. Analysis Strategy: Fuzzer/ASan Reports
When analyzing an ASan trace, do not just look at the crash line. Use the following workflow:

1.  **Identify the Buffer:** Which variable holds the memory? (e.g., `ctxt->input->buf`).
2.  **Find the last Mutation:** Where was this buffer last resized or reallocated? (`realloc`, `xmlBufGrow`).
3.  **Check the Pointer:** Is the pointer being dereferenced (`ptr`) actually pointing to the *current* address of the buffer?
    * 
    * *Visualizing the disconnect:* The buffer moved to a new Heap address, but the Stack pointer still points to the old Heap address.
4.  **Check the Offset:** If it's an overflow, is it an "Off-By-One" (logic error) or a "Wrap-Around" (integer overflow)?

## 5. Remediation Checklist
Before submitting a patch, verify:
* [ ] **Pointer Sync:** If I moved memory, did I update *all* pointers (base, cur, end) referencing it?
* [ ] **Error Safety:** If `realloc` fails, does the program crash on a NULL pointer or a freed pointer?
* [ ] **Overflow Safety:** Did I use `size - N < len` instead of `len + N > size`?
* [ ] **Initialization:** If I grew the buffer, is the new memory zeroed (if required by the parser)?
