/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <errno.h>
#include "seccomp_api.h"

static unsigned int seccomp_api_level = 0;

#ifndef seccomp
static int seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}
#endif

static int sys_chk_seccomp_syscall(void)
{
	int rc;
	rc = seccomp(SECCOMP_SET_MODE_STRICT, 1, NULL);
	if (rc < 0 && errno == EINVAL)
		return 1;
	return 0;

}

static int sys_chk_seccomp_flag(int flag)
{
	if (seccomp(SECCOMP_SET_MODE_FILTER, flag, NULL) == -1 &&
	    errno == EFAULT)
		return 1;
	return 0;
}

static int sys_chk_seccomp_action(uint32_t action)
{
	if (action == SCMP_ACT_KILL_PROCESS) {
		if (seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &action) == 0)
			return 1;
		return 0;
	} else if (action == SCMP_ACT_KILL_THREAD) {
		return 1;
	} else if (action == SCMP_ACT_TRAP) {
		return 1;
	} else if ((action == SCMP_ACT_ERRNO(action & 0x0000ffff)) &&
		   ((action & 0x0000ffff) < MAX_ERRNO)) {
		return 1;
	} else if (action == SCMP_ACT_TRACE(action & 0x0000ffff)) {
		return 1;
	} else if (action == SCMP_ACT_LOG) {
		if (seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &action) == 0)
			return 1;
		return 0;
	} else if (action == SCMP_ACT_ALLOW) {
		return 1;
	} else if (action == SCMP_ACT_NOTIFY) {
		struct seccomp_notif_sizes sizes;
		if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0)
			return 1;
		return 0;
	}

	return 0;
}

static unsigned int _seccomp_api_update(void)
{
	unsigned int level = 1;

	/* NOTE: level 1 is the base level, start checking at 2 */

	if (sys_chk_seccomp_syscall() &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC) == 1)
		level = 2;

	/* 4.14 */
	if (level == 2 &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_LOG) == 1 &&
	    sys_chk_seccomp_action(SCMP_ACT_LOG) == 1 &&
	    sys_chk_seccomp_action(SCMP_ACT_KILL_PROCESS) == 1)
		level = 3;

	/* 4.17 */
	if (level == 3 &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_SPEC_ALLOW) == 1)
		level = 4;

	/* 5.0 */
	if (level == 4 &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_NEW_LISTENER) == 1 &&
	    sys_chk_seccomp_action(SCMP_ACT_NOTIFY) == 1)
		level = 5;

	/* 5.7 */
	if (level == 5 &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC_ESRCH) == 1)
		level = 6;

	/* 5.19 */
	if (level == 6 &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_NEW_LISTENER |
	                         SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV) == 1)
		level = 7;

	/* 6.6 */
	if (level == 7 &&
	    sys_chk_seccomp_flag(SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP) == 1)
		level = 8;

	/* update the stored api level and return */
	seccomp_api_level = level;
	return seccomp_api_level;
}

unsigned int seccomp_api_get(void)
{
	if (seccomp_api_level >= 1)
		return seccomp_api_level;
	return _seccomp_api_update();
}
