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
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "helpers.h"
#include "../kselftest_harness.h"

#ifndef O_MAYEXEC
#define O_MAYEXEC		040000000
#endif

#define SYSCTL_MAYEXEC	"/proc/sys/fs/open_mayexec_enforce"

#define BIN_DIR		"./test-mount"
#define BIN_PATH	BIN_DIR "/file"
#define DIR_PATH	BIN_DIR "/directory"

#define ALLOWED		1
#define DENIED		0

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

static void ignore_mac(struct __test_metadata *_metadata, int override)
{
	cap_t caps;
	const cap_value_t cap_val[1] = {
		CAP_MAC_ADMIN,
	};

	caps = cap_get_proc();
	ASSERT_NE(NULL, caps);
	ASSERT_EQ(0, cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_val,
				override ? CAP_SET : CAP_CLEAR));
	ASSERT_EQ(0, cap_set_proc(caps));
	EXPECT_EQ(0, cap_free(caps));
}

static void test_omx(struct __test_metadata *_metadata,
		const char *const path, const int exec_allowed)
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
	if (exec_allowed) {
		ASSERT_LE(0, fd);
		EXPECT_EQ(0, close(fd));
	} else {
		ASSERT_EQ(-EACCES, fd);
	}
}

static void test_omx_dir_file(struct __test_metadata *_metadata,
		const char *const dir_path, const char *const file_path,
		const int exec_allowed)
{
	/*
	 * Directory execution is always denied since commit 73601ea5b7b1
	 * ("fs/open.c: allow opening only regular files during execve()").
	 */
	test_omx(_metadata, dir_path, DENIED);
	test_omx(_metadata, file_path, exec_allowed);
}

static void test_dir_file(struct __test_metadata *_metadata,
		const char *const dir_path, const char *const file_path,
		const int exec_allowed)
{
	/* Tests as root. */
	ignore_dac(_metadata, 1);
	test_omx_dir_file(_metadata, dir_path, file_path, exec_allowed);

	/* Tests without bypass. */
	ignore_dac(_metadata, 0);
	test_omx_dir_file(_metadata, dir_path, file_path, exec_allowed);
}

static void sysctl_write(struct __test_metadata *_metadata,
		const char *path, const char *value)
{
	int fd;
	size_t len_value;
	ssize_t len_wrote;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	len_value = strlen(value);
	len_wrote = write(fd, value, len_value);
	ASSERT_EQ(len_wrote, len_value);
	EXPECT_EQ(0, close(fd));
}

static void create_workspace(struct __test_metadata *_metadata,
		int mount_exec, int file_exec)
{
	int fd;

	/*
	 * Cleans previous workspace if any error previously happened (don't
	 * check errors).
	 */
	umount(BIN_DIR);
	rmdir(BIN_DIR);

	/* Creates a clean mount point. */
	ASSERT_EQ(0, mkdir(BIN_DIR, 00700));
	ASSERT_EQ(0, mount("test", BIN_DIR, "tmpfs",
				MS_MGC_VAL | (mount_exec ? 0 : MS_NOEXEC),
				"mode=0700,size=4k"));

	/* Creates a test file. */
	fd = open(BIN_PATH, O_CREAT | O_RDONLY | O_CLOEXEC,
			file_exec ? 00500 : 00400);
	ASSERT_LE(0, fd);
	EXPECT_EQ(0, close(fd));

	/* Creates a test directory. */
	ASSERT_EQ(0, mkdir(DIR_PATH, file_exec ? 00500 : 00400));
}

static void delete_workspace(struct __test_metadata *_metadata)
{
	ignore_mac(_metadata, 1);
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "0");

	/* There is no need to unlink BIN_PATH nor DIR_PATH. */
	ASSERT_EQ(0, umount(BIN_DIR));
	ASSERT_EQ(0, rmdir(BIN_DIR));
}

FIXTURE_DATA(mount_exec_file_exec) { };

FIXTURE_SETUP(mount_exec_file_exec)
{
	create_workspace(_metadata, 1, 1);
}

FIXTURE_TEARDOWN(mount_exec_file_exec)
{
	delete_workspace(_metadata);
}

TEST_F(mount_exec_file_exec, mount)
{
	/* Enforces mount exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "1");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, ALLOWED);
}

TEST_F(mount_exec_file_exec, file)
{
	/* Enforces file exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "2");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, ALLOWED);
}

TEST_F(mount_exec_file_exec, mount_file)
{
	/* Enforces mount and file exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "3");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, ALLOWED);
}

FIXTURE_DATA(mount_exec_file_noexec) { };

FIXTURE_SETUP(mount_exec_file_noexec)
{
	create_workspace(_metadata, 1, 0);
}

FIXTURE_TEARDOWN(mount_exec_file_noexec)
{
	delete_workspace(_metadata);
}

TEST_F(mount_exec_file_noexec, mount)
{
	/* Enforces mount exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "1");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, ALLOWED);
}

TEST_F(mount_exec_file_noexec, file)
{
	/* Enforces file exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "2");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED);
}

TEST_F(mount_exec_file_noexec, mount_file)
{
	/* Enforces mount and file exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "3");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED);
}

FIXTURE_DATA(mount_noexec_file_exec) { };

FIXTURE_SETUP(mount_noexec_file_exec)
{
	create_workspace(_metadata, 0, 1);
}

FIXTURE_TEARDOWN(mount_noexec_file_exec)
{
	delete_workspace(_metadata);
}

TEST_F(mount_noexec_file_exec, mount)
{
	/* Enforces mount exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "1");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED);
}

TEST_F(mount_noexec_file_exec, file)
{
	/* Enforces file exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "2");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, ALLOWED);
}

TEST_F(mount_noexec_file_exec, mount_file)
{
	/* Enforces mount and file exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "3");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED);
}

FIXTURE_DATA(mount_noexec_file_noexec) { };

FIXTURE_SETUP(mount_noexec_file_noexec)
{
	create_workspace(_metadata, 0, 0);
}

FIXTURE_TEARDOWN(mount_noexec_file_noexec)
{
	delete_workspace(_metadata);
}

TEST_F(mount_noexec_file_noexec, mount)
{
	/* Enforces mount exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "1");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED);
}

TEST_F(mount_noexec_file_noexec, file)
{
	/* Enforces file exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "2");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED);
}

TEST_F(mount_noexec_file_noexec, mount_file)
{
	/* Enforces mount and file exec check. */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "3");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED);
}

TEST(sysctl_access_write)
{
	int fd;
	ssize_t len_wrote;

	ignore_mac(_metadata, 1);
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "0");

	ignore_mac(_metadata, 0);
	fd = open(SYSCTL_MAYEXEC, O_WRONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	len_wrote = write(fd, "0", 1);
	ASSERT_EQ(len_wrote, -1);
	EXPECT_EQ(0, close(fd));

	ignore_mac(_metadata, 1);
}

TEST_HARNESS_MAIN
