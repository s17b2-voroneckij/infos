.code64
.text

.macro restore_context
	call get_prepare_current_thread_context

	mov %rax, %rcx
	mov 0x10(%rcx), %r11

	test %r11, %r11
	jz 1f

	xor %edx, %edx
	mov $7, %eax
	xrstor (%r11)

1:
	mov (%rcx), %rsp
	pop (%rcx)
	
	mov (%rsp), %rax
	wrfsbase %rax
	add $8, %rsp
	mov (%rsp), %rax
	wrgsbase %rax
	add $8, %rsp
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rbp
	pop %rdi
	pop %rsi
	pop %rdx
	pop %rcx
	pop %rbx
	pop %rax
	add $8, %rsp

.endm

.global _Unwind_ReturnToUser2
_Unwind_ReturnToUser2:
    restore_context
    iretq