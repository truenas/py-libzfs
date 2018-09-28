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

CFLAGS="-nostdinc -I/usr/src/sys/cddl/compat/opensolaris/uts/common/ -I/usr/src/cddl/compat/opensolaris/include/ -I/usr/src/sys/cddl/contrib/opensolaris/uts/common/
-I/usr/src/sys/cddl/contrib/opensolaris/uts/common/fs/zfs/ -I/usr/src/sys/cddl/compat/opensolaris/sys/ -I/usr/src/sys/cddl/compat/opensolaris/ -I/usr/src/cddl/lib/libumem 
-I/usr/src/usr/src/cddl/compat/opensolaris/ -I/usr/src/usr/src/cddl/compat/opensolaris -I/usr/src/cddl/compat/opensolaris/lib/libumem -I/usr/src/cddl/contrib/opensolaris/lib/libzpool/common 
-I/usr/src/sys/cddl/contrib/opensolaris/common/zfs -I/usr/src/sys/cddl/contrib/opensolaris/uts/common/sys -I/usr/src/cddl/contrib/opensolaris/head -I/usr/src/cddl/contrib/opensolaris/lib/libnvpair 
-I/usr/src/cddl/contrib/opensolaris/lib/libuutil/common -I/usr/src/cddl/contrib/opensolaris/lib/libzfs/common -I/usr/src/cddl/contrib/opensolaris/lib/libzfs_core/common ${CFLAGS} -I/usr/include"

LDFLAGS="-lzfs -lnvpair -lzfs_core -luutil -lgeom -v"

AC_DEFINE(NEED_SOLARIS_BOOLEAN)

SECTION_TITLE([RUNNING TESTS ON zfs.h HEADER])

AC_CHECK_HEADERS([sys/types.h], [], [AC_ERROR([A working lib is required])])
AC_CHECK_HEADERS([sys/fs/zfs.h], [], [AC_ERROR([A working zfs is required])],
[#include <sys/types.h>
])

dnl following is a valid check if zfs_max_dataset_name_len exists
AX_CHECK_DEFINE([sys/fs/zfs.h], [ZFS_MAX_DATASET_NAME_LEN], [AC_DEFINE(HAVE_ZFS_MAX_DATASET_NAME_LEN)], [])

dnl following is a check for a typedef in a header file
AX_CHECK_TYPEDEF([pool_scrub_cmd_t], sys/fs/zfs.h [, AC_DEFINE(HAVE_POOL_SCRUB_CMD_T)])


SECTION_TITLE([RUNNING TESTS ON libzfs.h HEADER])
dnl Following two defines are temporary for the time being as they stop some errors from happening if all the paths in cflags are defined in syncing with py-libzfs
AC_DEFINE(_SYS_ZFS_CONTEXT_H)
AC_DEFINE(_SYS_ZFS_IOCTL_H)
AC_DEFINE(_XPG6)


AC_CHECK_HEADERS([/usr/src/cddl/contrib/opensolaris/lib/libzfs/common/libzfs.h], [], [AC_ERROR([A working libzfs.h is required])],
[#include <sys/types.h>
#include <sys/mnttab.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
])


dnl Checking function signature of zpool_scan
AC_MSG_NOTICE([Checking function signature of zpool_scan])

AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
	[#include <libzfs.h>],
        [
            zpool_scan(NULL, NULL, NULL) /* ; */
        ])],
    [AC_DEFINE(HAVE_ZPOOL_SCAN_3) AC_MSG_NOTICE([3 params])], [AC_DEFINE(HAVE_ZPOOL_SCAN_2) AC_MSG_NOTICE([2 params])])

dnl Checking function signature of zfs_send_one
AC_MSG_NOTICE([Checking function signature of zfs_send_one])

AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
        [#include <libzfs.h>],
        [
            zfs_send_one(NULL, NULL, 0, 0) /* ; */
        ])],
    [AC_DEFINE(HAVE_ZFS_SEND_ONE_4) AC_MSG_NOTICE([4 params])], [AC_DEFINE(HAVE_ZFS_SEND_ONE_3) AC_MSG_NOTICE([3 params])])

dnl Checking existence of an enum value
AC_MSG_NOTICE([Checking EZFS_SCRUB_PAUSED presence])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
        [#include <libzfs.h>],
        [
            EZFS_SCRUB_PAUSED == EZFS_SCRUB_PAUSED /* ; */
        ])],
    [AC_DEFINE(HAVE_EZFS_SCRUB_PAUSED) AC_MSG_NOTICE([OK])], [AC_MSG_NOTICE([NOT FOUND])])

dnl Checking params for zfs_receive
AC_MSG_NOTICE([Checking params for zfs_receive])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
        [#include <libzfs.h>],
        [
            zfs_receive(NULL, NULL, NULL, NULL, 1, NULL) /* ; */
        ])],
    [AC_DEFINE(HAVE_ZFS_RECEIVE_6) AC_MSG_NOTICE([6 params])], [AC_DEFINE(HAVE_ZFS_RECEIVE_6) AC_MSG_NOTICE([5 params])])

dnl Checking existence of zfs_send_resume - if found, it is safe to assume that zfs_send_resume_token_to_nvlist exists too
AC_MSG_NOTICE([Checking existence of zfs_send_resume and zfs_send_resume_token_to_nvlist])

exists=0
AC_LINK_IFELSE([AC_LANG_PROGRAM(
         [#include <libzfs.h>],
         [            
            zfs_send_resume(NULL, NULL, 34, NULL) /* ; */
        ])],
    [exists=1], [AC_MSG_NOTICE([NOT FOUND])])

if test "$exists" == 1
then
AC_MSG_NOTICE([OK])
AC_DEFINE(HAVE_ZFS_SEND_RESUME)
AC_DEFINE(HAVE_ZFS_SEND_RESUME_TOKEN_TO_NVLIST)
fi

dnl Checking ZFS_MAXNAMELEN

AX_CHECK_DEFINE([libzfs.h], [ZFS_MAXNAMELEN], [AC_DEFINE(HAVE_ZFS_MAXNAMELEN)], [])

dnl Checking ZFS_MAXNAMELEN
AX_CHECK_DEFINE([libzfs.h], [ZPOOL_MAXNAMELEN], [AC_DEFINE(HAVE_ZPOOL_MAXNAMELEN)], [])

dnl AC_LANG_PUSH([C])
dnl AX_CHECK_FUNC_IN([/usr/src/sys/cddl/contrib/opensolaris/uts/common/sys/fs/zfs.h], [zfs_userquota_prop_prefixes])
dnl AC_LANG_POP([C])

SECTION_TITLE([GENERATING CONFIG.H])
AC_CONFIG_HEADERS(config.h)

dnl Process Makefile.in to create Makefile
AC_OUTPUT(Makefile)
