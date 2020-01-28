// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for control register pinning not being affected by SMRAM writes.
 */
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/kvm_para.h>
#include <linux/stringify.h>

#include "test_util.h"

#include "kvm_util.h"

#include "processor.h"
#include "apic.h"

#define VCPU_ID	      1

#define PAGE_SIZE  4096

#define SMRAM_SIZE 65536
#define SMRAM_MEMSLOT ((1 << 16) | 1)
#define SMRAM_PAGES (SMRAM_SIZE / PAGE_SIZE)
#define SMRAM_GPA 0x1000000
#define SMRAM_STAGE_SUCCESS 0xfe
#define SMRAM_STAGE_FAILURE 0xfd

#define XSTR(s) __stringify(s)

#define SYNC_PORT 0xe
#define DONE 0xff

#define CR0_PINNED X86_CR0_WP
#define CR4_PINNED_ONE (X86_CR4_SMAP | X86_CR4_UMIP)
#define CR4_PINNED_ZERO (X86_CR4_SMEP | X86_CR4_FSGSBASE)
#define CR4_ALL (CR4_PINNED_ONE | CR4_PINNED_ZERO)

/*
 * This is compiled as normal 64-bit code, however, SMI handler is executed
 * in real-address mode. To stay simple we're limiting ourselves to a mode
 * independent subset of asm here.
 * SMI handler always report back fixed stage SMRAM_STAGE_SUCCESS.
 */
uint8_t smi_handler_success[] = {
	0xb0, SMRAM_STAGE_SUCCESS,    /* mov $SMRAM_STAGE_SUCCESS, %al */
	0xe4, SYNC_PORT,              /* in $SYNC_PORT, %al */
	0x0f, 0xaa,                   /* rsm */
};

uint8_t smi_handler_fault[] = {
	0xb0, SMRAM_STAGE_FAILURE,    /* mov $SMRAM_STAGE_FAILURE, %al */
	0xe4, SYNC_PORT,              /* in $SYNC_PORT, %al */
	0x0f, 0xaa,                   /* rsm */
};

/* We opt not to use GUEST_SYNC() here because we also have to make a sync call
 * from SMM. As such, the address of the ucall struct we'd need to pass isn't
 * something we can put into the above machine code in a maintainable way
 */
static inline void sync_with_host(uint64_t phase)
{
	asm volatile("in $" XSTR(SYNC_PORT)", %%al\n"
		     : "+a" (phase));
}

void self_smi(void)
{
	wrmsr(APIC_BASE_MSR + (APIC_ICR >> 4),
	      APIC_DEST_SELF | APIC_INT_ASSERT | APIC_DM_SMI);
}

void guest_code(void)
{
	uint64_t apicbase = rdmsr(MSR_IA32_APICBASE);

	sync_with_host(1);

	wrmsr(MSR_IA32_APICBASE, apicbase | X2APIC_ENABLE);

	sync_with_host(2);

	set_cr0(get_cr0() | CR0_PINNED);

	wrmsr(MSR_KVM_CR0_PINNED_ONE, CR0_PINNED);

	sync_with_host(3);

	set_cr4(get_cr4() | CR4_PINNED_ONE);

	sync_with_host(4);

	wrmsr(MSR_KVM_CR4_PINNED_ONE, CR4_PINNED_ONE);
	wrmsr(MSR_KVM_CR4_PINNED_ZERO, CR4_PINNED_ZERO);

	sync_with_host(5);

	self_smi();

	sync_with_host(DONE);
}

int main(int argc, char *argv[])
{
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_vm *vm;
	struct kvm_run *run;
	struct kvm_x86_state *state;
	int failure, stage, stage_reported;
	u64 *cr;

	for (failure = 0; failure <= 1; failure++) {
		stage_reported = 0;

		/* Create VM */
		vm = vm_create_default(VCPU_ID, 0, guest_code);

		vcpu_set_cpuid(vm, VCPU_ID, kvm_get_supported_cpuid());

		run = vcpu_state(vm, VCPU_ID);

		vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, SMRAM_GPA,
					    SMRAM_MEMSLOT, SMRAM_PAGES, 0);
		TEST_ASSERT(vm_phy_pages_alloc(vm, SMRAM_PAGES, SMRAM_GPA, SMRAM_MEMSLOT)
			    == SMRAM_GPA, "could not allocate guest physical addresses?");

		memset(addr_gpa2hva(vm, SMRAM_GPA), 0x0, SMRAM_SIZE);
		if (failure) {
			memcpy(addr_gpa2hva(vm, SMRAM_GPA) + 0x8000, smi_handler_fault,
			       sizeof(smi_handler_fault));
		} else {
			memcpy(addr_gpa2hva(vm, SMRAM_GPA) + 0x8000, smi_handler_success,
			       sizeof(smi_handler_success));
		}
		vcpu_set_msr(vm, VCPU_ID, MSR_IA32_SMBASE, SMRAM_GPA);

		for (stage = 1;; stage++) {
			_vcpu_run(vm, VCPU_ID);

			memset(&regs, 0, sizeof(regs));
			vcpu_regs_get(vm, VCPU_ID, &regs);

			memset(&sregs, 0, sizeof(sregs));
			vcpu_sregs_get(vm, VCPU_ID, &sregs);

			/* stage_reported is currently the last stage reported */
			if (failure && stage_reported == SMRAM_STAGE_FAILURE) {
				/* Ensure that we exit on smram modification of CR4 */
				TEST_ASSERT(run->exit_reason == KVM_EXIT_INTERNAL_ERROR &&
					    run->internal.suberror == KVM_INTERNAL_ERROR_EMULATION,
					    "Stage %d: unexpected exit reason: %u, suberror: %u (%s),\n",
					    stage, run->exit_reason, run->internal.suberror,
					    exit_reason_str(run->exit_reason));
				if (run->exit_reason == KVM_EXIT_INTERNAL_ERROR)
					goto done;
			} else {
				TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
					    "Stage %d: unexpected exit reason: %u (%s),\n",
					    stage, run->exit_reason,
					    exit_reason_str(run->exit_reason));
			}

			stage_reported = regs.rax & 0xff;

			if (stage_reported == DONE) {
				TEST_ASSERT((sregs.cr0 & CR0_PINNED) == CR0_PINNED,
					    "Unexpected cr0. Bits missing: %llx",
					    sregs.cr0 ^ (CR0_PINNED | sregs.cr0));
				TEST_ASSERT((sregs.cr4 & CR4_ALL) == CR4_PINNED_ONE,
					    "Unexpected cr4. Bits missing: %llx, cr4: %llx",
					    sregs.cr4 ^ (CR4_ALL | sregs.cr4),
					    sregs.cr4);
				goto done;
			}

			TEST_ASSERT(stage_reported == stage ||
				    stage_reported == SMRAM_STAGE_SUCCESS ||
				    stage_reported == SMRAM_STAGE_FAILURE,
				    "Unexpected stage: #%x, got %x",
				    stage, stage_reported);

			/* Within SMM modify CR0/4 to not contain pinned bits. */
			if (stage_reported == SMRAM_STAGE_FAILURE) {
				cr = (u64 *)(addr_gpa2hva(vm, SMRAM_GPA + 0x8000 + 0x7f58));
				*cr &= ~CR0_PINNED;

				cr = (u64 *)(addr_gpa2hva(vm, SMRAM_GPA + 0x8000 + 0x7f48));
				/* Unset pinned one, set pinned zero */
				*cr &= ~CR4_PINNED_ONE;
				*cr |= CR4_PINNED_ZERO;
			}

			state = vcpu_save_state(vm, VCPU_ID);
			kvm_vm_release(vm);
			kvm_vm_restart(vm, O_RDWR);
			vm_vcpu_add(vm, VCPU_ID);
			vcpu_set_cpuid(vm, VCPU_ID, kvm_get_supported_cpuid());
			vcpu_load_state(vm, VCPU_ID, state);
			run = vcpu_state(vm, VCPU_ID);
			free(state);
		}

done:
		kvm_vm_free(vm);
	}
}
