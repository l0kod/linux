/*
 * Copyright (C) 2002 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <kern_util.h>
#include <sysdep/ptrace.h>
#include <sysdep/ptrace_user.h>
#include <sysdep/syscalls.h>
#include <os.h>

void handle_syscall(struct uml_pt_regs *r)
{
	struct pt_regs *regs = container_of(r, struct pt_regs, regs);
	long result;
	int syscall;

	/* Save the syscall register. */
	UPT_SYSCALL_NR(r) = PT_SYSCALL_NR(r->gp);

	/* Do the secure computing check first; failures should be fast. */
	if (secure_computing() == -1) {
		/* Do not put secure_computing() into syscall_trace_enter() to
		 * avoid forced syscall return value.
		 */
		return;
	}

	if (syscall_trace_enter(regs)) {
		result = -ENOSYS;
		goto out;
	}

	/* Get the syscall after being potentially updated with ptrace. */
	syscall = UPT_SYSCALL_NR(r);

	if ((syscall > __NR_syscall_max) || syscall < 0)
		result = -ENOSYS;
	else
		result = EXECUTE_SYSCALL(syscall, regs);

out:
	PT_REGS_SET_SYSCALL_RETURN(regs, result);

	syscall_trace_leave(regs);
}
