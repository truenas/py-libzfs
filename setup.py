#-
# Copyright (c) 2014 iXsystems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import os
import subprocess
from setuptools import setup

try:
    from Cython.Distutils import build_ext
    from Cython.Distutils.extension import Extension
except ImportError:
    raise ImportError("This package requires Cython to build properly. Please install it first.")

if "FREEBSD_SRC" not in os.environ:
    os.environ["FREEBSD_SRC"] = "/usr/src"


system_includes = [
    "${FREEBSD_SRC}/cddl/lib/libumem",
    "${FREEBSD_SRC}/sys/cddl/compat/opensolaris/",
    "${FREEBSD_SRC}/sys/cddl/compat/opensolaris",
    "${FREEBSD_SRC}/cddl/compat/opensolaris/include",
    "${FREEBSD_SRC}/cddl/compat/opensolaris/lib/libumem",
    "${FREEBSD_SRC}/cddl/contrib/opensolaris/lib/libzpool/common",
    "${FREEBSD_SRC}/sys/cddl/contrib/opensolaris/common/zfs",
    "${FREEBSD_SRC}/sys/cddl/contrib/opensolaris/uts/common/fs/zfs",
    "${FREEBSD_SRC}/sys/cddl/contrib/opensolaris/uts/common/sys",
    "${FREEBSD_SRC}/cddl/contrib/opensolaris/head",
    "${FREEBSD_SRC}/sys/cddl/contrib/opensolaris/uts/common",
    "${FREEBSD_SRC}/cddl/contrib/opensolaris/lib/libnvpair",
    "${FREEBSD_SRC}/cddl/contrib/opensolaris/lib/libuutil/common",
    "${FREEBSD_SRC}/cddl/contrib/opensolaris/lib/libzfs/common",
    "${FREEBSD_SRC}/cddl/contrib/opensolaris/lib/libzfs_core/common"
]

system_includes = [os.path.expandvars(x) for x in system_includes]

setup(
    name='libzfs',
    version='1.0',
    packages=[''],
    package_data={'': ['*.html', '*.c']},
    setup_requires=[
        'setuptools>=18.0',
        'Cython',
    ],
    cmdclass={'build_ext': build_ext},
    ext_modules=[
        Extension(
            "libzfs",
            ["libzfs.pyx"],
            libraries=["nvpair", "zfs", "zfs_core", "uutil", "geom"],
            extra_compile_args=["-DNEED_SOLARIS_BOOLEAN", "-D_XPG6", "-g"],
            cython_include_dirs=["./pxd"],
            include_dirs=system_includes,
            extra_link_args=["-g"],
        )
    ]
)
