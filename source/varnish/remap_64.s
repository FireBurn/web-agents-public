#
# The contents of this file are subject to the terms of the Common Development and
# Distribution License (the License). You may not use this file except in compliance with the
# License.
#
# You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
# specific language governing permission and limitations under the License.
#
# When distributing Covered Software, include this CDDL Header Notice in each file and include
# the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
# Header, with the fields enclosed by brackets [] replaced by your own identifying
# information: "Portions copyright [year] [name of copyright owner]".
#
# Copyright 2016 ForgeRock AS.
#
	.file	"remap_64.s"
	.text
	.globl	vmod_init                       # void vmod_init(const struct vrt_ctx *ctx, struct vmod_priv *priv, const char *conf);
	.type	vmod_init, @function            # ctx: request context, priv: vmod private, conf: agent configuration file; returns: void
vmod_init:                                                      
	pushq	%rdi							# save vCTX
	pushq	%rsi							# save vmod_priv
	pushq	%rdx							# save conf, conf
	call	get_extended_stack_enabled@plt  # obtains whether to use the stack switching process or not. Returns the value in eax
											# where 0 is not enabled and 1 is enabled. int get_extended_stack_enabled();
	test	%eax, %eax						# check return value
	je	.VINIT_DISABLED                     # continue if enabled, otherwise jump to disabled routine
	xorl	%edi, %edi 						# set rdi=0 for parameter in get_stack_size call
	call	get_stack_size@plt              # gets the requested stack size, returning the value in rax int get_stack_size(int iFunctionId [=0]);
	movl	%eax, %edi						# copy the size into rdi (ready for call to malloc) auto zeroing the upper 4 bytes
	pushq	%rdi							# and save the size on the stack
	call 	malloc@plt						# allocate the space
	test 	%rax, %rax						# check for null
	je	.VINIT_NOHEAP           			# if so jump to no heap routine, otherwise
	movq	%rax, %rcx						# backup the new stack base pointer
	popq 	%rdi							# rdi now contains the original size
	popq	%rdx							# restore conf
	addq	%rdi, %rax						# rax now holds the end of stack space address
	popq	%rsi							# restore vmod_priv
	popq	%rdi							# restore vCTX
	pushq	%rcx							# store the base address of the new stack on the original stack
	subq	$8, %rax						# rax now holds space for a unit_64 word at the top of the stack
	movq	%rsp, %rcx						# rcx now holds origin stack pointer
	and     $0xF0, %al                      # align the new stack pointer value.
	movq	%rax, %rsp						# stack now points to new base
	pushq	%rcx							# store original stack pointer on new stack
	pushq	%rbp							# store original frame pointer on new stack
	movq	%rsp, %rbp						# set new frame pointer position
	call	vmod_init_wp@plt				# call the real vmod init
	leave									# rbp now points to original frame psn
	popq	%rsp 							# restore original rsp
	popq	%rdi							# rdi (parameter 1) now contains the original base address of the new stack
	call	free@plt						# free the malloced space
	ret
.VINIT_NOHEAP:
	popq	%rax							# unwind the stack and restore the original values, continue into .VINIT_DISABLED
.VINIT_DISABLED:
	popq	%rdx							# conf
	popq	%rsi							# vmod_priv
	popq	%rdi							# vCTX
	jmp	vmod_init_wp@plt					# simply jump to original routine. This wrapper then is transparent and ret from original routine
											# will return to original caller as this wrapper didn't exist.

	.globl	vmod_authenticate               # unsigned int vmod_authenticate(const struct vrt_ctx *ctx, struct vmod_priv *priv);
	.type	vmod_authenticate, @function    # ctx: request context, priv: vmod private; returns: 1 (access allowed) or 0 (needs further action)
vmod_authenticate:
	pushq	%rdi							# save vCTX
	pushq	%rsi							# save vmod_priv
	call	get_extended_stack_enabled@plt  # obtains whether to use the stack switching process or not. Returns the value in eax
											# where 0 is not enabled and 1 is enabled. int get_extended_stack_enabled();
	test	%eax, %eax						# check return value
	je	.VAUTHN_DISABLED                    # continue if enabled, otherwise jump to disabled routine
	movl	$1, %edi 						# set rdi=1 for parameter in get_stack_size call
	call	get_stack_size@plt              # gets the requested stack size, returning the value in rax int get_stack_size(int iFunctionId [=1]);
	movl	%eax, %edi						# copy the size into rdi (ready for call to malloc) auto zeroing the upper 4 bytes
	pushq	%rdi							# and save the size on the stack
	call 	malloc@plt						# allocate the space
	test 	%rax, %rax						# check for null
	je	.VAUTHN_NOHEAP                      # if so jump to no heap routine, otherwise
	movq	%rax, %rcx						# backup the new stack base pointer
	popq 	%rdi							# rdi now contains the original size
	addq	%rdi, %rax						# rax now holds the end of stack space address
	popq	%rsi							# restore vmod_priv
	popq	%rdi							# restore vCTX
	pushq	%rcx							# store the base address of the new stack on the original stack
	subq	$8, %rax						# rax now holds space for a unit_64 word at the top of the stack
	movq	%rsp, %rcx						# rcx now holds origin stack pointer
	and     $0xF0, %al                      # align the new stack pointer value.
	movq	%rax, %rsp						# stack now points to new base
	pushq	%rcx							# store original stack pointer on new stack
	pushq	%rbp							# store original frame pointer on new stack
	movq	%rsp, %rbp						# set new frame pointer position
	call	vmod_authenticate_wp@plt        # call the real vmod authenticate
	leave									# rbp now points to original frame psn
	popq	%rsp 							# restore original rsp
	popq	%rdi							# rdi (parameter 1) now contains the original base address of the new stack
	pushq	%rax							# save the VCL_BOOL return value
	call	free@plt						# free the malloced space
	popq	%rax							# restore the VCL_BOOL return value
	ret
.VAUTHN_NOHEAP:
	popq	%rax							# unwind the stack and restore the original values, continue into .VAUTHN_DISABLED
.VAUTHN_DISABLED:
	popq	%rsi							# vmod_priv
	popq	%rdi							# vCTX
	jmp	vmod_authenticate_wp@plt            # simply jump to original routine. This wrapper then is transparent and ret from original routine
											# will return to original caller as this wrapper didn't exist.
	
	.globl	vmod_done                       # void vmod_done(const struct vrt_ctx *ctx, struct vmod_priv *priv);
	.type	vmod_done, @function            # ctx: request context, priv: vmod private; returns: void
vmod_done:
	pushq	%rdi							# save vCTX
	pushq	%rsi							# save vmod_priv
	call	get_extended_stack_enabled@plt  # obtains whether to use the stack switching process or not. Returns the value in eax
											# where 0 is not enabled and 1 is enabled. int get_extended_stack_enabled();
	test	%eax, %eax						# check return value
	je	.VDONE_DISABLED                     # continue if enabled, otherwise jump to disabled routine
	movl	$2, %edi 						# set rdi=2 for parameter in get_stack_size call
	call	get_stack_size@plt				# gets the requested stack size, returning the value in rax int get_stack_size(int iFunctionId [=2]);
	movl	%eax, %edi						# copy the size into rdi (ready for call to malloc) auto zeroing the upper 4 bytes
	pushq	%rdi							# and save the size on the stack
	call 	malloc@plt						# allocate the space
	test 	%rax, %rax						# check for null
	je	.VDONE_NOHEAP                       # if so jump to no heap routine, otherwise
	movq	%rax, %rcx						# backup the new stack base pointer
	popq 	%rdi							# rdi now contains the original size
	addq	%rdi, %rax						# rax now holds the end of stack space address
	popq	%rsi							# restore vmod_priv
	popq	%rdi							# restore vCTX
	pushq	%rcx							# store the base address of the new stack on the original stack
	subq	$8, %rax						# rax now holds space for a unit_64 word at the top of the stack
	movq	%rsp, %rcx						# rcx now holds origin stack pointer
	and     $0xF0, %al                     	# align the new stack pointer value.
	movq	%rax, %rsp						# stack now points to new base
	pushq	%rcx							# store original stack pointer on new stack
	pushq	%rbp							# store original frame pointer on new stack
	movq	%rsp, %rbp						# set new frame pointer position
	call	vmod_done_wp@plt				# call the real vmod done
	leave									# rbp now points to original frame psn
	popq	%rsp 							# restore original rsp
	popq	%rdi							# rdi (parameter 1) now contains the original base address of the new stack
	call	free@plt						# free the malloced space
	ret
.VDONE_NOHEAP:
	popq	%rax							# unwind the stack and restore the original values, continue into .VDONE_DISABLED
.VDONE_DISABLED:
	popq	%rsi							# vmod_priv
	popq	%rdi							# vCTX
	jmp	vmod_done_wp@plt                    # simply jump to original routine. This wrapper then is transparent and ret from original routine
											# will return to original caller as this wrapper didn't exist.
	
	.globl	vmod_ok                         # void vmod_ok(const struct vrt_ctx *ctx, struct vmod_priv *priv);
	.type	vmod_ok, @function              # ctx: request context, priv: vmod private; returns: void
vmod_ok:
	pushq	%rdi							# save vCTX
	pushq	%rsi							# save vmod_priv
	call	get_extended_stack_enabled@plt  # obtains whether to use the stack switching process or not. Returns the value in eax
											# where 0 is not enabled and 1 is enabled. int get_extended_stack_enabled();
	test	%eax, %eax						# check return value
	je	.VOK_DISABLED                       # continue if enabled, otherwise jump to disabled routine
	movl	$3, %edi 						# set rdi=3 for parameter in get_stack_size call
	call	get_stack_size@plt				# gets the requested stack size, returning the value in rax int get_stack_size(int iFunctionId [=3]);
	movl	%eax, %edi						# copy the size into rdi (ready for call to malloc) auto zeroing the upper 4 bytes
	pushq	%rdi							# and save the size on the stack
	call 	malloc@plt						# allocate the space
	test 	%rax, %rax						# check for null
	je	.VOK_NOHEAP                         # if so jump to no heap routine, otherwise
	movq	%rax, %rcx						# backup the new stack base pointer
	popq 	%rdi							# rdi now contains the original size
	addq	%rdi, %rax						# rax now holds the end of stack space address
	popq	%rsi							# restore vmod_priv
	popq	%rdi							# restore vCTX
	pushq	%rcx							# store the base address of the new stack on the original stack
	subq	$8, %rax						# rax now holds space for a unit_64 word at the top of the stack
	movq	%rsp, %rcx						# rcx now holds origin stack pointer
	and     $0xF0, %al                      # align the new stack pointer value.
	movq	%rax, %rsp						# stack now points to new base
	pushq	%rcx							# store original stack pointer on new stack
	pushq	%rbp							# store original frame pointer on new stack
	movq	%rsp, %rbp						# set new frame pointer position
	call	vmod_ok_wp@plt					# call the real vmod ok
	leave									# rbp now points to original frame psn
	popq	%rsp 							# restore original rsp
	popq	%rdi							# rdi (parameter 1) now contains the original base address of the new stack
	call	free@plt						# free the malloced space
	ret
.VOK_NOHEAP:
	popq	%rax							# unwind the stack and restore the original values, continue into .VOK_DISABLED
.VOK_DISABLED:
	popq	%rsi							# vmod_priv
	popq	%rdi							# vCTX
	jmp	vmod_ok_wp@plt                      # simply jump to original routine. This wrapper then is transparent and ret from original routine
											# will return to original caller as this wrapper didn't exist.
	
	.globl	vmod_cleanup                    # void vmod_cleanup(const struct vrt_ctx *ctx, struct vmod_priv *priv);
	.type	vmod_cleanup, @function         # ctx: request context, priv: vmod private; returns: void
vmod_cleanup:
	pushq	%rdi							# save vCTX
	pushq	%rsi							# save vmod_priv
	call	get_extended_stack_enabled@plt  # obtains whether to use the stack switching process or not. Returns the value in eax
											# where 0 is not enabled and 1 is enabled. int get_extended_stack_enabled();
	test	%eax, %eax						# check return value
	je	.VCLEANUP_DISABLED                  # continue if enabled, otherwise jump to disabled routine
	movl	$4, %edi 						# set rdi=4 for parameter in get_stack_size call
	call	get_stack_size@plt				# gets the requested stack size, returning the value in rax int get_stack_size(int iFunctionId [=4]);
	movl	%eax, %edi						# copy the size into rdi (ready for call to malloc) auto zeroing the upper 4 bytes
	pushq	%rdi							# and save the size on the stack
	call 	malloc@plt						# allocate the space
	test 	%rax, %rax						# check for null
	je	.VCLEANUP_NOHEAP                    # if so jump to no heap routine, otherwise
	movq	%rax, %rcx						# backup the new stack base pointer
	popq 	%rdi							# rdi now contains the original size
	addq	%rdi, %rax						# rax now holds the end of stack space address
	popq	%rsi							# restore vmod_priv
	popq	%rdi							# restore vCTX
	pushq	%rcx							# store the base address of the new stack on the original stack
	subq	$8, %rax						# rax now holds space for a unit_64 word at the top of the stack
	movq	%rsp, %rcx						# rcx now holds origin stack pointer
	and     $0xF0, %al                      # align the new stack pointer value.
	movq	%rax, %rsp						# stack now points to new base
	pushq	%rcx							# store original stack pointer on new stack
	pushq	%rbp							# store original frame pointer on new stack
	movq	%rsp, %rbp						# set new frame pointer position
	call	vmod_cleanup_wp@plt				# call the real vmod cleanup
	leave									# rbp now points to original frame psn
	popq	%rsp 							# restore original rsp
	popq	%rdi							# rdi (parameter 1) now contains the original base address of the new stack
	call	free@plt						# free the malloced space
	ret
.VCLEANUP_NOHEAP:
	popq	%rax							# unwind the stack and restore the original values, continue into .VCLEANUP_DISABLED
.VCLEANUP_DISABLED:
	popq	%rsi							# vmod_priv
	popq	%rdi							# vCTX
	jmp	vmod_cleanup_wp@plt                 # simply jump to original routine. This wrapper then is transparent and ret from original routine
											# will return to original caller as this wrapper didn't exist.
	
	.globl	vmod_request_cleanup            # void vmod_request_cleanup(const struct vrt_ctx *ctx, struct vmod_priv *priv);
	.type	vmod_request_cleanup, @function # ctx: request context, priv: vmod private; returns: void
vmod_request_cleanup:
	pushq	%rdi							# save vCTX
	pushq	%rsi							# save vmod_priv
	call	get_extended_stack_enabled@plt  # obtains whether to use the stack switching process or not. Returns the value in eax
											# where 0 is not enabled and 1 is enabled. int get_extended_stack_enabled();
	test	%eax, %eax						# check return value
	je	.VREQ_CLEANUP_DISABLED              # continue if enabled, otherwise jump to disabled routine
	movl	$5, %edi 						# set rdi=5 for parameter in get_stack_size call
	call	get_stack_size@plt				# gets the requested stack size, returning the value in rax int get_stack_size(int iFunctionId [=5]);
	movl	%eax, %edi						# copy the size into rdi (ready for call to malloc) auto zeroing the upper 4 bytes
	pushq	%rdi							# and save the size on the stack
	call 	malloc@plt						# allocate the space
	test 	%rax, %rax						# check for null
	je	.VREQ_CLEANUP_NOHEAP                # if so jump to no heap routine, otherwise
	movq	%rax, %rcx						# backup the new stack base pointer
	popq 	%rdi							# rdi now contains the original size
	addq	%rdi, %rax						# rax now holds the end of stack space address
	popq	%rsi							# restore vmod_priv
	popq	%rdi							# restore vCTX
	pushq	%rcx							# store the base address of the new stack on the original stack
	subq	$8, %rax						# rax now holds space for a unit_64 word at the top of the stack
	movq	%rsp, %rcx						# rcx now holds origin stack pointer
	and     $0xF0, %al                      # align the new stack pointer value.
	movq	%rax, %rsp						# stack now points to new base
	pushq	%rcx							# store original stack pointer on new stack
	pushq	%rbp							# store original frame pointer on new stack
	movq	%rsp, %rbp						# set new frame pointer position
	call	vmod_request_cleanup_wp@plt     # call the real vmod request cleanup
	leave									# rbp now points to original frame psn
	popq	%rsp 							# restore original rsp
	popq	%rdi							# rdi (parameter 1) now contains the original base address of the new stack
	call	free@plt						# free the malloced space
	ret
.VREQ_CLEANUP_NOHEAP:
	popq	%rax							# unwind the stack and restore the original values, continue into .VREQ_CLEANUP_DISABLED
.VREQ_CLEANUP_DISABLED:
	popq	%rsi							# vmod_priv
	popq	%rdi							# vCTX
	jmp	vmod_request_cleanup_wp@plt     	# simply jump to original routine. This wrapper then is transparent and ret from original routine
											# will return to original caller as this wrapper didn't exist.

	.globl	event_function              	# int event_function(const struct vrt_ctx *ctx, struct vmod_priv *priv, enum vcl_event_e e);
	.type	event_function, @function   	# ctx: request context, priv: vmod private, vcl_event_e: event type (VCL_EVENT_LOAD,VCL_EVENT_WARM,VCL_EVENT_COLD,VCL_EVENT_DISCARD); returns: 0 (unused)
event_function:
	pushq	%rdi							# save vCTX
	pushq	%rsi							# save vmod_priv
	pushq	%rdx							# save vcl_event
	call	get_extended_stack_enabled@plt  # obtains whether to use the stack switching process or not. Returns the value in eax
											# where 0 is not enabled and 1 is enabled. int getExtendedStackEnabled();
	test	%eax, %eax						# check return value
	je	.VEVENT_FN_DISABLED                 # continue if enabled, otherwise jump to disabled routine
	movl	$7, %edi 						# set rdi=7 for parameter in getStackSize call
	call	get_stack_size@plt				# gets the requested stack size, returning the value in rax int getStackSize(int iFunctionId [=7]);
	movl	%eax, %edi						# copy the size into rdi (ready for call to malloc) auto zeroing the upper 4 bytes
	pushq	%rdi							# and save the size on the stack
	call 	malloc@plt						# allocate the space
	test 	%rax, %rax						# check for null
	je	.VEVENT_FN_NOHEAP                   # if so jump to no heap routine, otherwise
	movq	%rax, %rcx						# backup the new stack base pointer
	popq 	%rdi							# rdi now contains the original size
	popq	%rdx							# restore vcl_event
	addq	%rdi, %rax						# rax now holds the end of stack space address
	popq	%rsi							# restore vmod_priv
	popq	%rdi							# restore vCTX
	pushq	%rcx							# store the base address of the new stack on the original stack
	subq	$8, %rax						# rax now holds space for a unit_64 word at the top of the stack
	movq	%rsp, %rcx						# rcx now holds origin stack pointer
	andb	$0XF0, %al						# align the new stack pointer value.
	movq	%rax, %rsp						# stack now points to new base
	pushq	%rcx							# store original stack pointer on new stack
	pushq	%rbp							# store original frame pointer on new stack
	movq	%rsp, %rbp						# set new frame pointer position
	call	event_function_wp@plt           # call the real event function
	leave									# rbp now points to original frame psn
	popq	%rsp 							# restore original rsp
	popq	%rdi							# rdi (parameter 1) now contains the original base address of the new stack
	pushq	%rax							# save the int return value
	call	free@plt						# free the malloced space
	popq	%rax							# restore the int return value
	ret
.VEVENT_FN_NOHEAP:
	popq	%rax							# unwind the stack and restore the original values, continue into .VEVENT_FN_DISABLED
.VEVENT_FN_DISABLED:
	popq	%rdx							# vcl_event
	popq	%rsi							# vmod_priv
	popq	%rdi							# vCTX
	jmp	event_function_wp@plt               # simply jump to original routine. This wrapper then is transparent and ret from original routine
											# will return to original caller as this wrapper didn't exist.
	
	.ident	"GCC: (GNU) 4.x"
	.section	.note.GNU-stack,"",@progbits
