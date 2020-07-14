// SPDX-License-Identifier: GPL-2.0
/*
 * Test O_MAYEXEC
 *
 * Copyright © 2018-2020 ANSSI
 *
 * Author: Mickaël Salaün <mic@digikod.net>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "helpers.h"
#include "../kselftest_harness.h"

#ifndef O_MAYEXEC
#define O_MAYEXEC		040000000
#endif

static const char sysctl_path[] = "/proc/sys/fs/open_mayexec_enforce";

static const char workdir_path[] = "./test-mount";
static const char file_path[] = "./test-mount/file";
static const char dir_path[] = "./test-mount/directory";

static void ignore_dac(struct __test_metadata *_metadata, int override)
{
	cap_t caps;
	const cap_value_t cap_val[2] = {
		CAP_DAC_OVERRIDE,
		CAP_DAC_READ_SEARCH,
	};

	caps = cap_get_proc();
	ASSERT_NE(NULL, caps);
	ASSERT_EQ(0, cap_set_flag(caps, CAP_EFFECTIVE, 2, cap_val,
				override ? CAP_SET : CAP_CLEAR));
	ASSERT_EQ(0, cap_set_proc(caps));
	EXPECT_EQ(0, cap_free(caps));
}

static void ignore_sys_admin(struct __test_metadata *_metadata, int override)
{
	cap_t caps;
	const cap_value_t cap_val[1] = {
		CAP_SYS_ADMIN,
	};

	caps = cap_get_proc();
	ASSERT_NE(NULL, caps);
	ASSERT_EQ(0, cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_val,
				override ? CAP_SET : CAP_CLEAR));
	ASSERT_EQ(0, cap_set_proc(caps));
	EXPECT_EQ(0, cap_free(caps));
}

static void test_omx(struct __test_metadata *_metadata,
		const char *const path, const int err_code)
{
	struct open_how how = {
		.flags = O_RDONLY | O_CLOEXEC,
	};
	int fd;

	/* Opens without O_MAYEXEC. */
	fd = sys_openat2(AT_FDCWD, path, &how);
	ASSERT_LE(0, fd);
	EXPECT_EQ(0, close(fd));

	how.flags |= O_MAYEXEC;

	/* Checks that O_MAYEXEC is ignored with open(2). */
	fd = open(path, how.flags);
	ASSERT_LE(0, fd);
	EXPECT_EQ(0, close(fd));

	/* Checks that O_MAYEXEC is ignored with openat(2). */
	fd = openat(AT_FDCWD, path, how.flags);
	ASSERT_LE(0, fd);
	EXPECT_EQ(0, close(fd));

	/* Opens with O_MAYEXEC. */
	fd = sys_openat2(AT_FDCWD, path, &how);
	if (!err_code) {
		ASSERT_LE(0, fd);
		EXPECT_EQ(0, close(fd));
	} else {
		ASSERT_EQ(err_code, fd);
	}
}

static void test_omx_dir_file(struct __test_metadata *_metadata, const int err_code)
{
	test_omx(_metadata, dir_path, -EISDIR);
	test_omx(_metadata, file_path, err_code);
}

static void test_dir_file(struct __test_metadata *_metadata, const int err_code)
{
	/* Tests as root. */
	ignore_dac(_metadata, 1);
	test_omx_dir_file(_metadata, err_code);

	/* Tests without bypass. */
	ignore_dac(_metadata, 0);
	test_omx_dir_file(_metadata, err_code);
}

static void sysctl_write_char(struct __test_metadata *_metadata, const char value)
{
	int fd;

	fd = open(sysctl_path, O_WRONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ASSERT_EQ(1, write(fd, &value, 1));
	EXPECT_EQ(0, close(fd));
}

static char sysctl_read_char(struct __test_metadata *_metadata)
{
	int fd;
	char sysctl_value;

	fd = open(sysctl_path, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ASSERT_EQ(1, read(fd, &sysctl_value, 1));
	EXPECT_EQ(0, close(fd));
	return sysctl_value;
}

FIXTURE(omayexec) {
	char initial_sysctl_value;
};

FIXTURE_VARIANT(omayexec) {
	const bool mount_exec;
	const bool file_exec;
	const int sysctl_err_code[3];
};

FIXTURE_VARIANT_ADD(omayexec, mount_exec_file_exec) {
	.mount_exec = true,
	.file_exec = true,
	.sysctl_err_code = {0, 0, 0},
};

FIXTURE_VARIANT_ADD(omayexec, mount_exec_file_noexec)
{
	.mount_exec = true,
	.file_exec = false,
	.sysctl_err_code = {0, -EACCES, -EACCES},
};

FIXTURE_VARIANT_ADD(omayexec, mount_noexec_file_exec)
{
	.mount_exec = false,
	.file_exec = true,
	.sysctl_err_code = {-EACCES, 0, -EACCES},
};

FIXTURE_VARIANT_ADD(omayexec, mount_noexec_file_noexec)
{
	.mount_exec = false,
	.file_exec = false,
	.sysctl_err_code = {-EACCES, -EACCES, -EACCES},
};

FIXTURE_SETUP(omayexec)
{
	int fd;

	/*
	 * Cleans previous workspace if any error previously happened (don't
	 * check errors).
	 */
	umount(workdir_path);
	rmdir(workdir_path);

	/* Creates a clean mount point. */
	ASSERT_EQ(0, mkdir(workdir_path, 00700));
	ASSERT_EQ(0, mount("test", workdir_path, "tmpfs", MS_MGC_VAL |
				(variant->mount_exec ? 0 : MS_NOEXEC),
				"mode=0700,size=4k"));

	/* Creates a test file. */
	fd = open(file_path, O_CREAT | O_RDONLY | O_CLOEXEC,
			variant->file_exec ? 00500 : 00400);
	ASSERT_LE(0, fd);
	EXPECT_EQ(0, close(fd));

	/* Creates a test directory. */
	ASSERT_EQ(0, mkdir(dir_path, variant->file_exec ? 00500 : 00400));

	/* Saves initial sysctl value. */
	self->initial_sysctl_value = sysctl_read_char(_metadata);

	/* Prepares for sysctl writes. */
	ignore_sys_admin(_metadata, 1);
}

FIXTURE_TEARDOWN(omayexec)
{
	/* Restores initial sysctl value. */
	sysctl_write_char(_metadata, self->initial_sysctl_value);

	/* There is no need to unlink file_path nor dir_path. */
	ASSERT_EQ(0, umount(workdir_path));
	ASSERT_EQ(0, rmdir(workdir_path));
}

TEST_F(omayexec, sysctl_0)
{
	/* Do not enforce anything. */
	sysctl_write_char(_metadata, '0');
	test_dir_file(_metadata, 0);
}

TEST_F(omayexec, sysctl_1)
{
	/* Enforces mount exec check. */
	sysctl_write_char(_metadata, '1');
	test_dir_file(_metadata, variant->sysctl_err_code[0]);
}

TEST_F(omayexec, sysctl_2)
{
	/* Enforces file exec check. */
	sysctl_write_char(_metadata, '2');
	test_dir_file(_metadata, variant->sysctl_err_code[1]);
}

TEST_F(omayexec, sysctl_3)
{
	/* Enforces mount and file exec check. */
	sysctl_write_char(_metadata, '3');
	test_dir_file(_metadata, variant->sysctl_err_code[2]);
}

TEST(sysctl_access_write)
{
	int fd;
	ssize_t ret;

	ignore_sys_admin(_metadata, 1);
	sysctl_write_char(_metadata, '0');

	ignore_sys_admin(_metadata, 0);
	fd = open(sysctl_path, O_WRONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ret = write(fd, "0", 1);
	ASSERT_EQ(-1, ret);
	ASSERT_EQ(EPERM, errno);
	EXPECT_EQ(0, close(fd));
}

TEST_HARNESS_MAIN
