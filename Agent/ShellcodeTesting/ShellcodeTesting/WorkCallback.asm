PUBLIC WorkCallback

.code
WorkCallback PROC
    ; rcx: PTP_CALLBACK_INSTANCE (not used in your assembly example)
    ; rdx: PVOID Context (pointer to NTALLOCATEVIRTUALMEMORY_ARGS)
    ; r8:  PTP_WORK (not used in your assembly example)

    ; Backup rdx (Context) to rbx
    mov rbx, rdx                ; rbx = Context (pointer to NTALLOCATEVIRTUALMEMORY_ARGS)
    
    ; Extract fields from the struct
    mov rax, qword ptr [rbx]    ; NtAllocateVirtualMemory
    mov rcx, qword ptr [rbx + 8] ; HANDLE ProcessHandle
    mov rdx, qword ptr [rbx + 10h] ; PVOID *BaseAddress
    xor r8, r8                  ; ULONG_PTR ZeroBits (set to 0)
    mov r9, qword ptr [rbx + 18h] ; PSIZE_T RegionSize
    mov r10, qword ptr [rbx + 20h] ; ULONG Protect
    mov qword ptr [rsp + 30h], r10 ; stack pointer for 6th argument
    mov r10, 3000h              ; ULONG AllocationType
    mov qword ptr [rsp + 28h], r10 ; stack pointer for 5th argument

    ; Jump to NtAllocateVirtualMemory
    jmp rax
WorkCallback ENDP
END
