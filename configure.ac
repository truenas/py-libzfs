AC_INIT(py-libzfs, 1.0)

AC_LANG(C)
AC_PROG_CC

define(SECTION_TITLE,
[
	echo >& AS_MESSAGE_FD
	echo '   $1   ' | sed -e's/./-/g' >&AS_MESSAGE_FD
	echo '   $1' >& AS_MESSAGE_FD
	echo '   $1   ' | sed -e's/./-/g' >&AS_MESSAGE_FD
])

dnl works for checking define statements in c
m4_include([m4/AX_CHECK_DEFINE.m4])

dnl check for type import
m4_include([m4/AX_CHECK_TYPEDEF.m4])

CFLAGS="-I/usr/src/sys/cddl/compat/opensolaris/ ${CFLAGS}"
LDFLAGS="-L/usr/src/sys/cddl/compat/opensolaris/ ${LDFLAGS}"

AC_DEFINE(NEED_SOLARIS_BOOLEAN)

SECTION_TITLE([CHECKING zfs.h HEADER])

AC_CHECK_HEADERS([sys/types.h], [], [AC_ERROR([A working lib is required])])
AC_CHECK_HEADERS([/usr/src/sys/cddl/contrib/opensolaris/uts/common/sys/fs/zfs.h], [], [AC_ERROR([A working zfs is required])],
[#include <sys/types.h>
])

SECTION_TITLE([RUNNING TESTS FOR ZFS_MAX_DATASET_NAME_LEN AND "pool_scrub_cmd_t"])
dnl following is a valid check if zfs_max_dataset_name_len exists
AX_CHECK_DEFINE([/usr/src/sys/cddl/contrib/opensolaris/uts/common/sys/fs/zfs.h], [ZFS_MAX_DATASET_NAME_LEN], [AC_DEFINE(HAVE_ZFS_MAX_DATASET_NAME_LEN)], [])

dnl following is a check for a typedef in a header file
AX_CHECK_TYPEDEF([pool_scrub_cmd_t], /usr/src/sys/cddl/contrib/opensolaris/uts/common/sys/fs/zfs.h [, AC_DEFINE(HAVE_POOL_SCRUB_CMD_T)])


dnl AC_LANG_PUSH([C])
dnl AX_CHECK_FUNC_IN([/usr/src/sys/cddl/contrib/opensolaris/uts/common/sys/fs/zfs.h], [zfs_userquota_prop_prefixes])
dnl AC_LANG_POP([C])

SECTION_TITLE([GENERATING CONFIG.H])
AC_CONFIG_HEADERS(config.h)

dnl Process Makefile.in to create Makefile
AC_OUTPUT(Makefile)
