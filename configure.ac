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

freebsd_src=${FREEBSD_SRC:=/usr/src}

dnl Setting appropriate CFLAGS
CFLAGS="-nostdinc -I${freebsd_src}/sys/cddl/compat/opensolaris/uts/common/ -I${freebsd_src}/cddl/compat/opensolaris/include/ -I${freebsd_src}/sys/cddl/contrib/opensolaris/uts/common/
-I${freebsd_src}/sys/cddl/contrib/opensolaris/uts/common/fs/zfs/ -I${freebsd_src}/sys/cddl/compat/opensolaris/sys/ -I${freebsd_src}/sys/cddl/compat/opensolaris/ -I${freebsd_src}/cddl/lib/libumem 
-I${freebsd_src}/sys/cddl/compat/opensolaris/ -I${freebsd_src}/sys/cddl/compat/opensolaris -I${freebsd_src}/cddl/compat/opensolaris/lib/libumem 
-I${freebsd_src}/cddl/contrib/opensolaris/lib/libzpool/common 
-I${freebsd_src}/sys/cddl/contrib/opensolaris/common/zfs -I${freebsd_src}/sys/cddl/contrib/opensolaris/uts/common/sys -I${freebsd_src}/cddl/contrib/opensolaris/head 
-I${freebsd_src}/cddl/contrib/opensolaris/lib/libnvpair 
-I${freebsd_src}/cddl/contrib/opensolaris/lib/libuutil/common -I${freebsd_src}/cddl/contrib/opensolaris/lib/libzfs/common -I${freebsd_src}/cddl/contrib/opensolaris/lib/libzfs_core/common ${CFLAGS} 
-I/usr/include"

dnl Setting appropriate LDFLAGS
LDFLAGS="-lzfs -lnvpair -lzfs_core -luutil -lgeom -v"

AC_DEFINE(NEED_SOLARIS_BOOLEAN)

SECTION_TITLE([RUNNING TESTS ON zfs.h HEADER])

AC_CHECK_HEADERS([sys/types.h], [], [AC_ERROR([A working sys/types header is required])])
AC_CHECK_HEADERS([sys/fs/zfs.h], [], [AC_ERROR([A working zfs header is required])],[
	#include <sys/types.h>
])

dnl following is a valid check if zfs_max_dataset_name_len exists
AX_CHECK_DEFINE(
	[sys/fs/zfs.h], [ZFS_MAX_DATASET_NAME_LEN],
	[AC_SUBST(HAVE_ZFS_MAX_DATASET_NAME_LEN, 1)],
	[AC_SUBST(HAVE_ZFS_MAX_DATASET_NAME_LEN, 0)]
)


dnl Checking typedef pool_scrub_cmd_t in zfs header
AC_MSG_NOTICE([Checking typedef pool_scrub_cmt_t in zfs header])

AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[#include <sys/fs/zfs.h>],
		[
			int i = sizeof(pool_scrub_cmd_t);
			i = i; /* ; */
		]
	)],
	[AC_SUBST(HAVE_POOL_SCRUB_CMD_T, 1) AC_MSG_NOTICE([OK])],
	[AC_SUBST(HAVE_POOL_SCRUB_CMD_T, 0) AC_MSG_NOTICE([Not found])]
)


SECTION_TITLE([RUNNING TESTS ON libzfs.h HEADER])
dnl Following two defines are temporary for the time being as they stop some errors from happening if all the paths in cflags are defined in syncing with py-libzfs
AC_DEFINE(_SYS_ZFS_CONTEXT_H)
AC_DEFINE(_SYS_ZFS_IOCTL_H)
AC_DEFINE(_XPG6)


AC_CHECK_HEADERS([/usr/src/cddl/contrib/opensolaris/lib/libzfs/common/libzfs.h], [], [AC_ERROR([A working libzfs header is required])], [
	#include <sys/types.h>
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
		]
	)],
	[AC_SUBST(HAVE_ZPOOL_SCAN, 3) AC_MSG_NOTICE([3 params])],
	[AC_SUBST(HAVE_ZPOOL_SCAN, 2) AC_MSG_NOTICE([2 params])]
)


dnl Checking function signature of zfs_send_one
AC_MSG_NOTICE([Checking function signature of zfs_send_one])

AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[#include <libzfs.h>],
		[
			zfs_send_one(NULL, NULL, 0, 0) /* ; */
		]
	)],
	[AC_SUBST(HAVE_ZFS_SEND_ONE, 4) AC_MSG_NOTICE([4 params])],
	[AC_SUBST(HAVE_ZFS_SEND_ONE, 3) AC_MSG_NOTICE([3 params])]
)


dnl Checking existence of an enum value
AC_MSG_NOTICE([Checking EZFS_SCRUB_PAUSED presence])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[#include <libzfs.h>],
		[
			EZFS_SCRUB_PAUSED == EZFS_SCRUB_PAUSED /* ; */
		]
	)],
	[AC_SUBST(HAVE_EZFS_SCRUB_PAUSED, 1) AC_MSG_NOTICE([OK])],
	[AC_SUBST(HAVE_EZFS_SCRUB_PAUSED, 0) AC_MSG_NOTICE([NOT FOUND])]
)


dnl Checking typedef sendflags_t in zfs header
AC_MSG_NOTICE([Checking typedef sendflags_t in libzfs header])

AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[#include <libzfs.h>],
		[
			int i = sizeof(sendflags_t);
			i = i; /* ; */
		]
	)],
	[AC_SUBST(HAVE_SENDFLAGS_T_TYPEDEF, 1) AC_MSG_NOTICE([OK])],
	[AC_SUBST(HAVE_SENDFLAGS_T_TYPEDEF, 0) AC_MSG_NOTICE([Not found])]
)


dnl Checking existence of an enum value
AC_MSG_NOTICE([Checking LZC_SEND_FLAG_EMBED_DATA presence])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[#include <libzfs.h>],
		[
			LZC_SEND_FLAG_EMBED_DATA == LZC_SEND_FLAG_EMBED_DATA /* ; */
		]
	)],
	[AC_SUBST(HAVE_LZC_SEND_FLAG_EMBED_DATA, 1) AC_MSG_NOTICE([OK])],
	[AC_SUBST(HAVE_LZC_SEND_FLAG_EMBED_DATA, 0) AC_MSG_NOTICE([NOT FOUND])]
)


dnl Checking params for zfs_receive
AC_MSG_NOTICE([Checking params for zfs_receive])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[#include <libzfs.h>],
		[
			zfs_receive(NULL, NULL, NULL, NULL, 1, NULL) /* ; */
		]
	)],
	[AC_SUBST(HAVE_ZFS_RECEIVE, 6) AC_MSG_NOTICE([6 params])],
	[AC_SUBST(HAVE_ZFS_RECEIVE, 5) AC_MSG_NOTICE([5 params])]
)


dnl Checking existence of zfs_send_resume - if found, it is safe to assume that zfs_send_resume_token_to_nvlist exists too
AC_MSG_NOTICE([Checking existence of zfs_send_resume and zfs_send_resume_token_to_nvlist])

exists=0
AC_LINK_IFELSE([AC_LANG_PROGRAM(
		[#include <libzfs.h>],
		[            
			zfs_send_resume(NULL, NULL, 0, NULL) /* ; */
        	]
	)],
	[exists=1],
	[AC_SUBST(HAVE_ZFS_SEND_RESUME, 0) AC_SUBST(HAVE_ZFS_SEND_RESUME_TOKEN_TO_NVLIST, 0) AC_MSG_NOTICE([NOT FOUND])]
)


if test "$exists" == 1
then
	AC_MSG_NOTICE([OK])
	AC_SUBST(HAVE_ZFS_SEND_RESUME, 1)
	AC_SUBST(HAVE_ZFS_SEND_RESUME_TOKEN_TO_NVLIST, 1)
fi


dnl Checking ZFS_MAXNAMELEN

AX_CHECK_DEFINE([libzfs.h], [ZFS_MAXNAMELEN], [AC_SUBST(HAVE_ZFS_MAXNAMELEN, 1)], [AC_SUBST(HAVE_ZFS_MAXNAMELEN, 0)])


dnl Checking ZPOOL_MAXNAMELEN

AX_CHECK_DEFINE([libzfs.h], [ZPOOL_MAXNAMELEN], [AC_SUBST(HAVE_ZPOOL_MAXNAMELEN, 1)], [AC_SUBST(HAVE_ZPOOL_MAXNAMELEN, 0)])


dnl Checking for resumable member in recvflags_t struct
AC_MSG_NOTICE([Checking for resumable member in recvflags_t struct])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[#include <libzfs.h>],
		[
			recvflags_t t;
			t.resumable = 1 /* ; */
 		]
	)],
	[AC_SUBST(HAVE_RECVFLAGS_T_RESUMABLE, 1) AC_MSG_NOTICE([OK])],
	[AC_SUBST(HAVE_RECVFLAGS_T_RESUMABLE, 0) AC_MSG_NOTICE([NOT FOUND])]
)


dnl Checking for compress member in sendflags_t struct
AC_MSG_NOTICE([Checking for compress member in sendflags_t struct])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[#include <libzfs.h>],
		[
			sendflags_t t;
			t.compress = 1 /* ; */
		]
	)],
	[AC_SUBST(HAVE_SENDFLAGS_T_COMPRESS, 1) AC_MSG_NOTICE([OK])],
	[AC_SUBST(HAVE_SENDFLAGS_T_COMPRESS, 0) AC_MSG_NOTICE([NOT FOUND])]
)


SECTION_TITLE([RUNNING TESTS ON libzfs_core.h HEADER])


AC_CHECK_HEADERS([libzfs_core.h], [], [AC_ERROR([A working libzfs_core header is required])], [
	#include <sys/types.h>
	#include <sys/param.h>
])


dnl Checking lzc_bookmark existence
AC_MSG_NOTICE([Verifying lzc_bookmark existence])

exists=0
AC_LINK_IFELSE([AC_LANG_PROGRAM(
		[#include <libzfs_core.h>],
		[
			lzc_bookmark(NULL, NULL) /* ; */
		]
	)],
	[exists=1],
	[AC_MSG_NOTICE([NOT FOUND])]
)


if test "$exists" == 1
then
	AC_MSG_NOTICE([OK])
	AC_SUBST(HAVE_LZC_BOOKMARK, 1)

	dnl Verifying existence and params of lzc_send_space
	AC_MSG_NOTICE([Verifying existence and params of lzc_send_space])

	exists=0
	AC_LINK_IFELSE([AC_LANG_PROGRAM(
			[#include <libzfs_core.h>],
			[
				lzc_send_space(NULL, NULL, LZC_SEND_FLAG_EMBED_DATA, NULL) /* ; */
			]
		)],
		[exists=1],
		[AC_MSG_NOTICE([NOT FOUND])]
	)

	if test "$exists" == 1
	then

		AC_MSG_NOTICE([4 params])
		AC_SUBST(HAVE_LZC_SEND_SPACE, 4)

	else

		AC_MSG_NOTICE([3 params])
		AC_SUBST(HAVE_LZC_SEND_SPACE, 3)
	fi

else

	AC_MSG_NOTICE([lzc_send_space function not found])
	AC_SUBST(HAVE_LZC_BOOKMARK, 0)
	AC_SUBST(HAVE_LZC_SEND_SPACE, 0)

fi


SECTION_TITLE([GENERATING CONFIG.H])
AC_CONFIG_FILES([pxd/config.pxi])


dnl Process Makefile.in to create Makefile
AC_OUTPUT(Makefile)
