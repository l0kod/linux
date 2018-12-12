// SPDX-License-Identifier: GPL-2.0
/*
 * Yama tests - O_MAYEXEC
 *
 * Copyright © 2018 ANSSI
 *
 * Author: Mickaël Salaün <mickael.salaun@ssi.gouv.fr>
 */

#include <errno.h>
#include <fcntl.h> /* O_CLOEXEC */
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* strlen */
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/stat.h> /* mkdir */
#include <unistd.h> /* unlink, rmdir */

#include "../kselftest_harness.h"

#ifndef O_MAYEXEC
#define O_MAYEXEC      040000000
#endif

#define SYSCTL_MAYEXEC	"/proc/sys/kernel/yama/open_mayexec_enforce"

#define BIN_DIR		"./test-mount"
#define BIN_PATH	BIN_DIR "/file"
#define DIR_PATH	BIN_DIR "/directory"

#define ALLOWED		1
#define DENIED		0

static void test_omx(struct __test_metadata *_metadata,
		const char *const path, const int exec_allowed)
{
	int fd;

	/* without O_MAYEXEC */
	fd = open(path, O_RDONLY | O_CLOEXEC);
	ASSERT_NE(-1, fd);
	EXPECT_FALSE(close(fd));

	/* with O_MAYEXEC */
	fd = open(path, O_RDONLY | O_CLOEXEC | O_MAYEXEC);
	if (exec_allowed) {
		/* open should succeed */
		ASSERT_NE(-1, fd);
		EXPECT_FALSE(close(fd));
	} else {
		/* open should return EACCES */
		ASSERT_EQ(-1, fd);
		ASSERT_EQ(EACCES, errno);
	}
}

static void ignore_dac(struct __test_metadata *_metadata, int override)
{
	cap_t caps;
	const cap_value_t cap_val[2] = {
		CAP_DAC_OVERRIDE,
		CAP_DAC_READ_SEARCH,
	};

	caps = cap_get_proc();
	ASSERT_TRUE(!!caps);
	ASSERT_FALSE(cap_set_flag(caps, CAP_EFFECTIVE, 2, cap_val,
				override ? CAP_SET : CAP_CLEAR));
	ASSERT_FALSE(cap_set_proc(caps));
	EXPECT_FALSE(cap_free(caps));
}

static void test_dir_file(struct __test_metadata *_metadata,
		const char *const dir_path, const char *const file_path,
		const int exec_allowed, const int only_file_perm)
{
	if (only_file_perm) {
		/* test as root */
		ignore_dac(_metadata, 1);
		/* always allowed because of generic_permission() use */
		test_omx(_metadata, dir_path, ALLOWED);
	}

	/* without bypass */
	ignore_dac(_metadata, 0);
	test_omx(_metadata, dir_path, exec_allowed);
	test_omx(_metadata, file_path, exec_allowed);
}

static void sysctl_write(struct __test_metadata *_metadata,
		const char *path, const char *value)
{
	int fd;
	size_t len_value;
	ssize_t len_wrote;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	ASSERT_NE(-1, fd);
	len_value = strlen(value);
	len_wrote = write(fd, value, len_value);
	ASSERT_EQ(len_wrote, len_value);
	EXPECT_FALSE(close(fd));
}

static void create_workspace(struct __test_metadata *_metadata,
		int mount_exec, int file_exec)
{
	int fd;

	/*
	 * Cleanup previous workspace if any error previously happened (don't
	 * check errors).
	 */
	umount(BIN_DIR);
	rmdir(BIN_DIR);

	/* create a clean mount point */
	ASSERT_FALSE(mkdir(BIN_DIR, 00700));
	ASSERT_FALSE(mount("test", BIN_DIR, "tmpfs",
				MS_MGC_VAL | (mount_exec ? 0 : MS_NOEXEC),
				"mode=0700,size=4k"));

	/* create a test file */
	fd = open(BIN_PATH, O_CREAT | O_RDONLY | O_CLOEXEC,
			file_exec ? 00500 : 00400);
	ASSERT_NE(-1, fd);
	EXPECT_NE(-1, close(fd));

	/* create a test directory */
	ASSERT_FALSE(mkdir(DIR_PATH, file_exec ? 00500 : 00400));
}

static void delete_workspace(struct __test_metadata *_metadata)
{
	ignore_dac(_metadata, 1);
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "0");

	/* no need to unlink BIN_PATH nor DIR_PATH */
	ASSERT_FALSE(umount(BIN_DIR));
	ASSERT_FALSE(rmdir(BIN_DIR));
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
	/* enforce mount exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "1");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, ALLOWED, 0);
}

TEST_F(mount_exec_file_exec, file)
{
	/* enforce file exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "2");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, ALLOWED, 0);
}

TEST_F(mount_exec_file_exec, mount_file)
{
	/* enforce mount and file exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "3");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, ALLOWED, 0);
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
	/* enforce mount exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "1");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, ALLOWED, 0);
}

TEST_F(mount_exec_file_noexec, file)
{
	/* enforce file exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "2");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED, 1);
}

TEST_F(mount_exec_file_noexec, mount_file)
{
	/* enforce mount and file exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "3");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED, 1);
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
	/* enforce mount exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "1");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED, 0);
}

TEST_F(mount_noexec_file_exec, file)
{
	/* enforce file exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "2");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, ALLOWED, 0);
}

TEST_F(mount_noexec_file_exec, mount_file)
{
	/* enforce mount and file exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "3");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED, 0);
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
	/* enforce mount exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "1");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED, 0);
}

TEST_F(mount_noexec_file_noexec, file)
{
	/* enforce file exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "2");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED, 1);
}

TEST_F(mount_noexec_file_noexec, mount_file)
{
	/* enforce mount and file exec check */
	sysctl_write(_metadata, SYSCTL_MAYEXEC, "3");
	test_dir_file(_metadata, DIR_PATH, BIN_PATH, DENIED, 0);
}

TEST_HARNESS_MAIN
