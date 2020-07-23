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
#include <sys/sysmacros.h>
#include <unistd.h>

#include "helpers.h"
#include "../kselftest_harness.h"

#ifndef O_MAYEXEC
#define O_MAYEXEC		040000000
#endif

static const char sysctl_path[] = "/proc/sys/fs/open_mayexec_enforce";

static const char workdir_path[] = "./test-mount";
static const char reg_file_path[] = "./test-mount/regular_file";
static const char dir_path[] = "./test-mount/directory";
static const char symlink_path[] = "./test-mount/symlink";
static const char block_dev_path[] = "./test-mount/block_device";
static const char char_dev_path[] = "./test-mount/character_device";
static const char fifo_path[] = "./test-mount/fifo";
static const char sock_path[] = "./test-mount/socket";

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
		const char *const path, const int no_mayexec_err_code,
		const int mayexec_err_code)
{
	struct open_how how = {
		.flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC,
	};
	int fd;

	/* Do not block on pipes. */
	if (path == fifo_path)
		how.flags |= O_NONBLOCK;

	/* Opens without O_MAYEXEC. */
	fd = sys_openat2(AT_FDCWD, path, &how);
	if (!no_mayexec_err_code) {
		ASSERT_LE(0, fd) {
			TH_LOG("Failed to openat2 %s: %d", path, -fd);
		}
		EXPECT_EQ(0, close(fd));
	} else {
		ASSERT_EQ(no_mayexec_err_code, fd) {
			TH_LOG("Wrong error for openat2 %s: %d", path, -fd);
		}
	}

	how.flags |= O_MAYEXEC;

	/* Checks that O_MAYEXEC is ignored with open(2). */
	fd = open(path, how.flags);
	if (!no_mayexec_err_code) {
		ASSERT_LE(0, fd) {
			TH_LOG("Failed to open %s: %d", path, errno);
		}
		EXPECT_EQ(0, close(fd));
	} else {
		ASSERT_EQ(no_mayexec_err_code, -errno);
	}

	/* Checks that O_MAYEXEC is ignored with openat(2). */
	fd = openat(AT_FDCWD, path, how.flags);
	if (!no_mayexec_err_code) {
		ASSERT_LE(0, fd) {
			TH_LOG("Failed to openat %s: %d", path, errno);
		}
		EXPECT_EQ(0, close(fd));
	} else {
		ASSERT_EQ(no_mayexec_err_code, -errno);
	}

	/* Opens with O_MAYEXEC. */
	fd = sys_openat2(AT_FDCWD, path, &how);
	if (!mayexec_err_code) {
		ASSERT_LE(0, fd) {
			TH_LOG("Failed to openat2 %s: %d", path, -fd);
		}
		EXPECT_EQ(0, close(fd));
	} else {
		ASSERT_EQ(mayexec_err_code, fd) {
			TH_LOG("Wrong error for openat2 %s: %d", path, -fd);
		}
	}
}

static void test_file_types(struct __test_metadata *_metadata, const int err_code,
		const bool has_policy)
{
	test_omx(_metadata, reg_file_path, 0, err_code);
	test_omx(_metadata, dir_path, 0, -EISDIR);
	test_omx(_metadata, symlink_path, -ELOOP, -ELOOP);
	test_omx(_metadata, block_dev_path, 0, has_policy ? -EACCES : 0);
	test_omx(_metadata, char_dev_path, 0, has_policy ? -EACCES : 0);
	test_omx(_metadata, fifo_path, 0, has_policy ? -EACCES : 0);
	test_omx(_metadata, sock_path, -ENXIO, has_policy ? -EACCES : -ENXIO);
}

static void test_files(struct __test_metadata *_metadata, const int err_code,
		const bool has_policy)
{
	/* Tests as root. */
	ignore_dac(_metadata, 1);
	test_file_types(_metadata, err_code, has_policy);

	/* Tests without bypass. */
	ignore_dac(_metadata, 0);
	test_file_types(_metadata, err_code, has_policy);
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

	/* Creates a regular file. */
	ASSERT_EQ(0, mknod(reg_file_path, S_IFREG | (variant->file_exec ? 0500 : 0400), 0));
	/* Creates a directory. */
	ASSERT_EQ(0, mkdir(dir_path, variant->file_exec ? 0500 : 0400));
	/* Creates a symlink pointing to the regular file. */
	ASSERT_EQ(0, symlink("regular_file", symlink_path));
	/* Creates a character device: /dev/null. */
	ASSERT_EQ(0, mknod(char_dev_path, S_IFCHR | 0400, makedev(1, 3)));
	/* Creates a block device: /dev/loop0 */
	ASSERT_EQ(0, mknod(block_dev_path, S_IFBLK | 0400, makedev(7, 0)));
	/* Creates a fifo. */
	ASSERT_EQ(0, mknod(fifo_path, S_IFIFO | 0400, 0));
	/* Creates a socket. */
	ASSERT_EQ(0, mknod(sock_path, S_IFSOCK | 0400, 0));

	/* Saves initial sysctl value. */
	self->initial_sysctl_value = sysctl_read_char(_metadata);

	/* Prepares for sysctl writes. */
	ignore_sys_admin(_metadata, 1);
}

FIXTURE_TEARDOWN(omayexec)
{
	/* Restores initial sysctl value. */
	sysctl_write_char(_metadata, self->initial_sysctl_value);

	/* There is no need to unlink the test files. */
	ASSERT_EQ(0, umount(workdir_path));
	ASSERT_EQ(0, rmdir(workdir_path));
}

TEST_F(omayexec, sysctl_0)
{
	/* Do not enforce anything. */
	sysctl_write_char(_metadata, '0');
	test_files(_metadata, 0, false);
}

TEST_F(omayexec, sysctl_1)
{
	/* Enforces mount exec check. */
	sysctl_write_char(_metadata, '1');
	test_files(_metadata, variant->sysctl_err_code[0], true);
}

TEST_F(omayexec, sysctl_2)
{
	/* Enforces file exec check. */
	sysctl_write_char(_metadata, '2');
	test_files(_metadata, variant->sysctl_err_code[1], true);
}

TEST_F(omayexec, sysctl_3)
{
	/* Enforces mount and file exec check. */
	sysctl_write_char(_metadata, '3');
	test_files(_metadata, variant->sysctl_err_code[2], true);
}

FIXTURE(cleanup) {
	char initial_sysctl_value;
};

FIXTURE_SETUP(cleanup)
{
	/* Saves initial sysctl value. */
	self->initial_sysctl_value = sysctl_read_char(_metadata);
}

FIXTURE_TEARDOWN(cleanup)
{
	/* Restores initial sysctl value. */
	ignore_sys_admin(_metadata, 1);
	sysctl_write_char(_metadata, self->initial_sysctl_value);
}

TEST_F(cleanup, sysctl_access_write)
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
