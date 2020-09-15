// SPDX-License-Identifier: GPL-2.0

#include <asm/kvm_para.h>
#include <asm/hypervisor.h>

#include <linux/kobject.h>
#include <linux/sysfs.h>

static ssize_t pv_cr_pinning_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", kvm_paravirt_cr_pinning_enabled);
}

static struct kobj_attribute pv_cr_pinning_attr = __ATTR_RO(pv_cr_pinning);

static struct attribute *kvm_hypervisor_attrs[] = {
	&pv_cr_pinning_attr.attr,
	NULL,
};

static const struct attribute_group hypervisor_attr_group = {
	.attrs = kvm_hypervisor_attrs,
};

static int __init kvm_sysfs_cr_pinning_init(void)
{
	return sysfs_create_group(hypervisor_kobj, &hypervisor_attr_group);
}

static int __init kvm_sysfs_init(void)
{
	if (!kvm_para_available() || nopv)
		return -ENODEV;

	return kvm_sysfs_cr_pinning_init();
}
device_initcall(kvm_sysfs_init);
