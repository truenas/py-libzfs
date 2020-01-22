# encoding: utf-8
# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

import os
import stat
import enum
import errno
import itertools
import logging
import time
import threading
cimport libzfs
cimport zfs
cimport nvpair
from datetime import datetime
from libc.errno cimport errno
from libc.string cimport memset, strncpy
from libc.stdlib cimport realloc

GLOBAL_CONTEXT_LOCK = threading.Lock()
logger = logging.getLogger(__name__)


include "config.pxi"
include "nvpair.pxi"
include "converter.pxi"


class DatasetType(enum.IntEnum):
    FILESYSTEM = zfs.ZFS_TYPE_FILESYSTEM
    VOLUME = zfs.ZFS_TYPE_VOLUME
    SNAPSHOT = zfs.ZFS_TYPE_SNAPSHOT
    BOOKMARK = zfs.ZFS_TYPE_BOOKMARK


class Error(enum.IntEnum):
    SUCCESS = libzfs.EZFS_SUCCESS
    NOMEM = libzfs.EZFS_NOMEM
    BADPROP = libzfs.EZFS_BADPROP
    PROPREADONLY = libzfs.EZFS_PROPREADONLY
    PROPTYPE = libzfs.EZFS_PROPTYPE
    PROPNONINHERIT = libzfs.EZFS_PROPNONINHERIT
    PROPSPACE = libzfs.EZFS_PROPSPACE
    BADTYPE = libzfs.EZFS_BADTYPE
    BUSY = libzfs.EZFS_BUSY
    EXISTS = libzfs.EZFS_EXISTS
    NOENT = libzfs.EZFS_NOENT
    BADSTREAM = libzfs.EZFS_BADSTREAM
    DSREADONLY = libzfs.EZFS_DSREADONLY
    VOLTOOBIG = libzfs.EZFS_VOLTOOBIG
    INVALIDNAME = libzfs.EZFS_INVALIDNAME
    BADRESTORE = libzfs.EZFS_BADRESTORE
    BADBACKUP = libzfs.EZFS_BADBACKUP
    BADTARGET = libzfs.EZFS_BADTARGET
    NODEVICE = libzfs.EZFS_NODEVICE
    BADDEV = libzfs.EZFS_BADDEV
    NOREPLICAS = libzfs.EZFS_NOREPLICAS
    RESILVERING = libzfs.EZFS_RESILVERING
    BADVERSION = libzfs.EZFS_BADVERSION
    POOLUNAVAIL = libzfs.EZFS_POOLUNAVAIL
    DEVOVERFLOW = libzfs.EZFS_DEVOVERFLOW
    BADPATH = libzfs.EZFS_BADPATH
    CROSSTARGET = libzfs.EZFS_CROSSTARGET
    ZONED = libzfs.EZFS_ZONED
    MOUNTFAILED = libzfs.EZFS_MOUNTFAILED
    UMOUNTFAILED = libzfs.EZFS_UMOUNTFAILED
    UNSHARENFSFAILED = libzfs.EZFS_UNSHARENFSFAILED
    SHARENFSFAILED = libzfs.EZFS_SHARENFSFAILED
    PERM = libzfs.EZFS_PERM
    NOSPC = libzfs.EZFS_NOSPC
    FAULT = libzfs.EZFS_FAULT
    IO = libzfs.EZFS_IO
    INTR = libzfs.EZFS_INTR
    ISSPARE = libzfs.EZFS_ISSPARE
    INVALCONFIG = libzfs.EZFS_INVALCONFIG
    RECURSIVE = libzfs.EZFS_RECURSIVE
    NOHISTORY = libzfs.EZFS_NOHISTORY
    POOLPROPS = libzfs.EZFS_POOLPROPS
    POOL_NOTSUP = libzfs.EZFS_POOL_NOTSUP
    INVALARG = libzfs.EZFS_POOL_INVALARG
    NAMETOOLONG = libzfs.EZFS_NAMETOOLONG
    OPENFAILED = libzfs.EZFS_OPENFAILED
    NOCAP = libzfs.EZFS_NOCAP
    LABELFAILED = libzfs.EZFS_LABELFAILED
    BADWHO = libzfs.EZFS_BADWHO
    BADPERM = libzfs.EZFS_BADPERM
    BADPERMSET = libzfs.EZFS_BADPERMSET
    NODELEGATION = libzfs.EZFS_NODELEGATION
    UNSHARESMBFAILED = libzfs.EZFS_UNSHARESMBFAILED
    SHARESMBFAILED = libzfs.EZFS_SHARESMBFAILED
    BADCACHE = libzfs.EZFS_BADCACHE
    ISL2CACHE = libzfs.EZFS_ISL2CACHE
    VDEVNOTSUP = libzfs.EZFS_VDEVNOTSUP
    NOTSUP = libzfs.EZFS_NOTSUP
    SPARE = libzfs.EZFS_ACTIVE_SPARE
    LOGS = libzfs.EZFS_UNPLAYED_LOGS
    RELE = libzfs.EZFS_REFTAG_RELE
    HOLD = libzfs.EZFS_REFTAG_HOLD
    TAGTOOLONG = libzfs.EZFS_TAGTOOLONG
    PIPEFAILED = libzfs.EZFS_PIPEFAILED
    THREADCREATEFAILED = libzfs.EZFS_THREADCREATEFAILED
    ONLINE = libzfs.EZFS_POSTSPLIT_ONLINE
    SCRUBBING = libzfs.EZFS_SCRUBBING
    SCRUB = libzfs.EZFS_NO_SCRUB
    DIFF = libzfs.EZFS_DIFF
    DIFFDATA = libzfs.EZFS_DIFFDATA
    POOLREADONLY = libzfs.EZFS_POOLREADONLY
    UNKNOWN = libzfs.EZFS_UNKNOWN


class PropertySource(enum.IntEnum):
    NONE = zfs.ZPROP_SRC_NONE
    DEFAULT = zfs.ZPROP_SRC_DEFAULT
    TEMPORARY = zfs.ZPROP_SRC_TEMPORARY
    LOCAL = zfs.ZPROP_SRC_LOCAL
    INHERITED = zfs.ZPROP_SRC_INHERITED
    RECEIVED = zfs.ZPROP_SRC_RECEIVED


class VDevState(enum.IntEnum):
    UNKNOWN = zfs.VDEV_STATE_UNKNOWN
    CLOSED = zfs.VDEV_STATE_CLOSED
    OFFLINE = zfs.VDEV_STATE_OFFLINE
    REMOVED = zfs.VDEV_STATE_REMOVED
    CANT_OPEN = zfs.VDEV_STATE_CANT_OPEN
    FAULTED = zfs.VDEV_STATE_FAULTED
    DEGRADED = zfs.VDEV_STATE_DEGRADED
    HEALTHY = zfs.VDEV_STATE_HEALTHY


class VDevAuxState(enum.IntEnum):
    NONE = zfs.VDEV_AUX_NONE
    OPEN_FAILED = zfs.VDEV_AUX_OPEN_FAILED
    CORRUPT_DATA = zfs.VDEV_AUX_CORRUPT_DATA
    NO_REPLICAS = zfs.VDEV_AUX_NO_REPLICAS
    BAD_GUID_SUM = zfs.VDEV_AUX_BAD_GUID_SUM
    TOO_SMALL = zfs.VDEV_AUX_TOO_SMALL
    BAD_LABEL = zfs.VDEV_AUX_BAD_LABEL
    VERSION_NEWER = zfs.VDEV_AUX_VERSION_NEWER
    VERSION_OLDER = zfs.VDEV_AUX_VERSION_OLDER
    UNSUP_FEAT = zfs.VDEV_AUX_UNSUP_FEAT
    SPARED = zfs.VDEV_AUX_SPARED
    ERR_EXCEEDED = zfs.VDEV_AUX_ERR_EXCEEDED
    IO_FAILURE = zfs.VDEV_AUX_IO_FAILURE
    BAD_LOG = zfs.VDEV_AUX_BAD_LOG
    EXTERNAL = zfs.VDEV_AUX_EXTERNAL
    SPLIT_POOL = zfs.VDEV_AUX_SPLIT_POOL
    IF HAVE_VDEV_AUX_ASHIFT_TOO_BIG:
        ASHIFT_TOO_BIG = zfs.VDEV_AUX_ASHIFT_TOO_BIG


class PoolState(enum.IntEnum):
    ACTIVE = zfs.POOL_STATE_ACTIVE
    EXPORTED = zfs.POOL_STATE_EXPORTED
    DESTROYED = zfs.POOL_STATE_DESTROYED
    SPARE = zfs.POOL_STATE_SPARE
    L2CACHE = zfs.POOL_STATE_L2CACHE
    UNINITIALIZED = zfs.POOL_STATE_UNINITIALIZED
    UNAVAIL = zfs.POOL_STATE_UNAVAIL
    POTENTIALLY_ACTIVE = zfs.POOL_STATE_POTENTIALLY_ACTIVE


class ScanFunction(enum.IntEnum):
    NONE = zfs.POOL_SCAN_NONE
    SCRUB = zfs.POOL_SCAN_SCRUB
    RESILVER = zfs.POOL_SCAN_RESILVER


class PoolStatus(enum.IntEnum):
    CORRUPT_CACHE = libzfs.ZPOOL_STATUS_CORRUPT_CACHE
    MISSING_DEV_R = libzfs.ZPOOL_STATUS_MISSING_DEV_R
    MISSING_DEV_NR = libzfs.ZPOOL_STATUS_MISSING_DEV_NR
    CORRUPT_LABEL_R = libzfs.ZPOOL_STATUS_CORRUPT_LABEL_R
    CORRUPT_LABEL_NR = libzfs.ZPOOL_STATUS_CORRUPT_LABEL_NR
    BAD_GUID_SUM = libzfs.ZPOOL_STATUS_BAD_GUID_SUM
    CORRUPT_POOL = libzfs.ZPOOL_STATUS_CORRUPT_POOL
    CORRUPT_DATA = libzfs.ZPOOL_STATUS_CORRUPT_DATA
    FAILING_DEV = libzfs.ZPOOL_STATUS_FAILING_DEV
    VERSION_NEWER = libzfs.ZPOOL_STATUS_VERSION_NEWER
    HOSTID_MISMATCH = libzfs.ZPOOL_STATUS_HOSTID_MISMATCH
    IO_FAILURE_WAIT = libzfs.ZPOOL_STATUS_IO_FAILURE_WAIT
    IO_FAILURE_CONTINUE = libzfs.ZPOOL_STATUS_IO_FAILURE_CONTINUE
    BAD_LOG = libzfs.ZPOOL_STATUS_BAD_LOG
    UNSUP_FEAT_READ = libzfs.ZPOOL_STATUS_UNSUP_FEAT_READ
    UNSUP_FEAT_WRITE = libzfs.ZPOOL_STATUS_UNSUP_FEAT_WRITE
    FAULTED_DEV_R = libzfs.ZPOOL_STATUS_FAULTED_DEV_R
    FAULTED_DEV_NR = libzfs.ZPOOL_STATUS_FAULTED_DEV_NR
    VERSION_OLDER = libzfs.ZPOOL_STATUS_VERSION_OLDER
    FEAT_DISABLED = libzfs.ZPOOL_STATUS_FEAT_DISABLED
    RESILVERING = libzfs.ZPOOL_STATUS_RESILVERING
    OFFLINE_DEV = libzfs.ZPOOL_STATUS_OFFLINE_DEV
    REMOVED_DEV = libzfs.ZPOOL_STATUS_REMOVED_DEV
    IF HAVE_ZPOOL_STATUS_NON_NATIVE_ASHIFT:
        NON_NATIVE_ASHIFT = libzfs.ZPOOL_STATUS_NON_NATIVE_ASHIFT
    OK = libzfs.ZPOOL_STATUS_OK


class ScanState(enum.IntEnum):
    NONE = zfs.DSS_NONE
    SCANNING = zfs.DSS_SCANNING
    FINISHED = zfs.DSS_FINISHED
    CANCELED = zfs.DSS_CANCELED


class ZIOType(enum.IntEnum):
    NONE = zfs.ZIO_TYPE_NULL
    READ = zfs.ZIO_TYPE_READ
    WRITE = zfs.ZIO_TYPE_WRITE
    FREE = zfs.ZIO_TYPE_FREE
    CLAIM = zfs.ZIO_TYPE_CLAIM
    IOCTL = zfs.ZIO_TYPE_IOCTL


class FeatureState(enum.Enum):
    DISABLED = 0
    ENABLED = 1
    ACTIVE = 2


class SendFlag(enum.Enum):
    IF HAVE_SENDFLAGS_T_VERBOSITY:
        VERBOSITY = 0
    ELSE:
        VERBOSE = 0
    REPLICATE = 1
    DOALL = 2
    FROMORIGIN = 3
    DEDUP = 3
    PROPS = 4
    DRYRUN = 5
    PARSABLE = 6
    PROGRESS = 7
    LARGEBLOCK = 8
    EMBED_DATA = 9
    IF HAVE_SENDFLAGS_T_COMPRESS:
        COMPRESS = 10


class DiffRecordType(enum.Enum):
    ADD = '+'
    REMOVE = '-'
    MODIFY = 'M'
    RENAME = 'R'


class DiffFileType(enum.Enum):
    BLOCK = 'B'
    CHAR = 'C'
    FILE = 'F'
    DIRECTORY = '/'
    SYMLINK = '@'
    SOCKET = '='


IF HAVE_ZFS_MAX_DATASET_NAME_LEN:
    cdef enum:
        MAX_DATASET_NAME_LEN = zfs.ZFS_MAX_DATASET_NAME_LEN
ELSE:
    cdef enum:
        MAX_DATASET_NAME_LEN = libzfs.ZFS_MAXNAMELEN


cdef struct iter_state:
    uintptr_t *array
    size_t length
    size_t alloc


cdef struct prop_iter_state:
    zfs.zfs_type_t type
    void *props


class DiffRecord(object):
    def __init__(self, raw):
        timestamp, cmd, typ, rest = raw.split(maxsplit=3)
        paths = rest.split('->', maxsplit=2)
        self.raw = raw
        self.timestamp = datetime.utcfromtimestamp(float(timestamp))
        self.cmd = DiffRecordType(cmd)
        self.type = DiffFileType(typ)
        self.path = paths[0].strip()

        if self.cmd == DiffRecordType.RENAME:
            self.oldpath = paths[1].strip()

    def __str__(self):
        return self.raw

    def __repr__(self):
        return str(self)

    def __getstate__(self):
        return {
            'timestamp': self.timestamp,
            'cmd': self.cmd.name,
            'type': self.type.name,
            'path': self.path,
            'oldpath': getattr(self, 'oldpath', None)
        }



IF HAVE_LZC_SEND_FLAG_EMBED_DATA:
    class SendFlags(enum.IntEnum):
        EMBED_DATA = libzfs.LZC_SEND_FLAG_EMBED_DATA


class ZFSException(RuntimeError):
    def __init__(self, code, message):
        super(ZFSException, self).__init__(message)
        self.code = code

    def __reduce__(self):
        return (self.__class__, (self.code, self.args))


class ZFSVdevStatsException(ZFSException):
    def __init__(self, code):
        super(ZFSVdevStatsException, self).__init__(code, 'Failed to fetch ZFS Vdev Stats')


cdef class ZFS(object):
    cdef libzfs.libzfs_handle_t* handle
    cdef boolean_t mnttab_cache_enable
    cdef int history
    cdef char *history_prefix
    proptypes = {}

    def __cinit__(self, history=True, history_prefix='', mnttab_cache=True):
        cdef zfs.zfs_type_t c_type
        cdef prop_iter_state iter
        self.mnttab_cache_enable=mnttab_cache

        with nogil:
            self.handle = libzfs.libzfs_init()

        if isinstance(history, bool):
            self.history = history
        else:
            raise ZFSException(Error.BADTYPE, 'history is a boolean parameter')

        if self.history:
            if isinstance(history_prefix, str):
                self.history_prefix = history_prefix
            else:
                raise ZFSException(Error.BADTYPE, 'history_prefix is a string parameter')

        for t in DatasetType.__members__.values():
            proptypes = []
            c_type = <zfs.zfs_type_t>t
            iter.type = c_type
            iter.props = <void *>proptypes
            with nogil:
                libzfs.zprop_iter(self.__iterate_props, <void*>&iter, True, True, c_type)

            props = self.proptypes.setdefault(t, [])
            if set(proptypes) != set(props):
                self.proptypes[t] = proptypes

    def __enter__(self):
        GLOBAL_CONTEXT_LOCK.acquire()
        return self

    def __exit__(self, exc_type, value, traceback):
        self.__libzfs_fini()
        GLOBAL_CONTEXT_LOCK.release()
        if exc_type is not None:
            raise

    def __libzfs_fini(self):
        if self.handle:
            with nogil:
                libzfs.libzfs_fini(self.handle)

            self.handle = NULL

    def __dealloc__(self):
        ZFS.__libzfs_fini(self)

    def __getstate__(self):
        return [p.__getstate__() for p in self.pools]

    @staticmethod
    cdef int __iterate_props(int proptype, void *arg) nogil:
        cdef prop_iter_state *iter
        cdef boolean_t ret = False

        iter = <prop_iter_state *>arg

        IF HAVE_ZFS_PROP_VALID_FOR_TYPE == 3:
            ret = zfs.zfs_prop_valid_for_type(proptype, iter.type, ret)
        ELSE:
            ret = zfs.zfs_prop_valid_for_type(proptype, iter.type)

        if not ret:
            return zfs.ZPROP_CONT

        with gil:
            proptypes = <object>iter.props
            proptypes.append(proptype)
            return zfs.ZPROP_CONT

    @staticmethod
    cdef int __iterate_pools(libzfs.zpool_handle_t *handle, void *arg) nogil:
        with gil:
            pools = <object>arg
            pools.append(<uintptr_t>handle)

    cdef object get_error(self):
        return ZFSException(
            Error(libzfs.libzfs_errno(self.handle)),
            libzfs.libzfs_error_description(self.handle)
        )

    cdef ZFSVdev make_vdev_tree(self, topology):
        cdef ZFSVdev root
        root = ZFSVdev(self, zfs.VDEV_TYPE_ROOT)
        root.children = topology.get('data', [])

        if 'cache' in topology:
            root.nvlist[zfs.ZPOOL_CONFIG_L2CACHE] = [(<ZFSVdev>i).nvlist for i in topology['cache']]

        if 'spare' in topology:
            root.nvlist[zfs.ZPOOL_CONFIG_SPARES] = [(<ZFSVdev>i).nvlist for i in topology['spare']]

        if 'log' in topology:
            for i in topology['log']:
                (<ZFSVdev>i).nvlist[zfs.ZPOOL_CONFIG_IS_LOG] = 1L
                root.add_child_vdev(i)

        return root

    @staticmethod
    cdef int __dataset_handles(libzfs.zfs_handle_t* handle, void *arg) nogil:
        cdef int prop_id
        cdef char csrcstr[MAX_DATASET_NAME_LEN + 1]
        cdef char crawvalue[libzfs.ZFS_MAXPROPLEN + 1]
        cdef char cvalue[libzfs.ZFS_MAXPROPLEN + 1]
        cdef zfs.zprop_source_t csource
        cdef const char *name
        cdef zfs.zfs_type_t typ

        cdef nvpair.nvlist_t *nvlist

        name = libzfs.zfs_get_name(handle)
        typ = libzfs.zfs_get_type(handle)
        nvlist = libzfs.zfs_get_user_props(handle)

        with gil:
            dataset_type = DatasetType(typ)
            data_list = <object> arg
            configuration_data = data_list[0]
            data = data_list[1]
            children = []
            child_data = [configuration_data, {}]
            properties = {}

            for key, value in NVList(<uintptr_t>nvlist).items() if configuration_data['user_props'] else []:
                src = 'NONE'
                if value.get('source'):
                    src = value.pop('source')
                    if src == name:
                        src = PropertySource.LOCAL.name
                    elif src == '$recvd':
                        src = PropertySource.RECEIVED.name
                    else:
                        src = PropertySource.INHERITED.name

                properties[key] = {
                    'value': value.get('value'),
                    'rawvalue': value.get('value'),
                    'source': src,
                    'parsed': value.get('value')
                }

            for prop_name, prop_id in configuration_data['props'].get(dataset_type, {}).items():
                with nogil:
                    strncpy(cvalue, '', libzfs.ZFS_MAXPROPLEN + 1)
                    strncpy(crawvalue, '', libzfs.ZFS_MAXPROPLEN + 1)
                    strncpy(csrcstr, '', MAX_DATASET_NAME_LEN + 1)

                    libzfs.zfs_prop_get(
                        handle, prop_id, cvalue, libzfs.ZFS_MAXPROPLEN,
                        &csource, csrcstr, MAX_DATASET_NAME_LEN, False
                    )

                    libzfs.zfs_prop_get(
                        handle, prop_id, crawvalue, libzfs.ZFS_MAXPROPLEN,
                        NULL, NULL, 0, True
                    )

                properties[prop_name] = {
                    'parsed': parse_zfs_prop(prop_name, crawvalue),
                    'rawvalue': crawvalue,
                    'value': cvalue,
                    'source': PropertySource(<int>csource).name
                }

        libzfs.zfs_iter_filesystems(handle, ZFS.__dataset_handles, <void*>child_data)

        with gil:
            data[name] = {}
            child_data = child_data[1]

            data[name].update({
                'properties': properties,
                'id': name,
                'type': dataset_type.name,
                'children': list(child_data.values()),
                'name': name,
                'pool': configuration_data['pool']
            })
            for top_level_prop in configuration_data['top_level_props']:
                data[name][top_level_prop] = properties.get(top_level_prop, {}).get('value')

                if top_level_prop == 'mountpoint' and data[name][top_level_prop] == 'none':
                    data[name]['mountpoint'] = None

        libzfs.zfs_close(handle)

    def datasets_serialized(self, props=None, top_level_props=None, user_props=True):
        cdef libzfs.zfs_handle_t* handle
        cdef const char *c_name
        cdef int prop_id

        prop_mapping = {}
        if top_level_props is None:
            if props is None or 'mountpoint' in props:
                # We want to add default mountpoint key here to keep existing behavior.
                top_level_props = ['mountpoint']
            else:
                top_level_props = []

        # If props is None, we include all properties, if it's an empty list, no property is retrieved
        for dataset_type in [DatasetType.FILESYSTEM, DatasetType.VOLUME] if props is None or len(props) else []:
            prop_mapping[dataset_type] = {}
            for prop_id in ZFS.proptypes[dataset_type]:
                with nogil:
                    prop_name = libzfs.zfs_prop_to_name(prop_id)

                if props is None or prop_name in props:
                    prop_mapping[dataset_type][prop_name] = prop_id

        all_props = set(itertools.chain(*[prop_mapping[t] for t in prop_mapping]))
        for top_level_prop in top_level_props:
            if top_level_prop not in all_props:
                raise ValueError(f'{top_level_prop} should be present in props.')

        for p in self.pools:
            c_name = handle = NULL
            name = p.name
            c_name = name

            dataset = [
                {
                    'pool': name,
                    'props': prop_mapping,
                    'top_level_props': top_level_props,
                    'user_props': user_props,
                },
                {}
            ]

            with nogil:
                handle = libzfs.zfs_open(self.handle, c_name, zfs.ZFS_TYPE_FILESYSTEM)
                if handle == NULL:
                    with gil:
                        e_args = self.get_error().args
                        logger.error(
                            'Failed to retrieve root dataset handle for %s: %s', c_name, e_args[0] if e_args else ''
                        )
                        continue
                else:
                    ZFS.__dataset_handles(handle, <void*>dataset)

            yield dataset[1][name]

    @staticmethod
    cdef int __snapshot_details(libzfs.zfs_handle_t *handle, void *arg) nogil:
        cdef int prop_id, ret, simple_handle, holds, mounted
        cdef char csrcstr[MAX_DATASET_NAME_LEN + 1]
        cdef char crawvalue[libzfs.ZFS_MAXPROPLEN + 1]
        cdef char cvalue[libzfs.ZFS_MAXPROPLEN + 1]
        cdef zfs.zprop_source_t csource
        cdef const char *name, *mntpt
        cdef nvpair.nvlist_t *ptr, *nvlist

        with gil:
            snap_list = <object> arg
            configuration_data = snap_list[0]
            pool = configuration_data['pool']
            props = configuration_data['props']
            holds = configuration_data['holds']
            mounted = configuration_data['mounted']
            properties = {}
            simple_handle = len(props) == 1 and 'name' in props
            snap_data = {}

        IF HAVE_ZFS_ITER_SNAPSHOTS == 6:
            libzfs.zfs_iter_snapshots(handle, simple_handle, ZFS.__snapshot_details, <void*>snap_list, 0, 0)
        ELSE:
            libzfs.zfs_iter_snapshots(handle, simple_handle, ZFS.__snapshot_details, <void*>snap_list)

        if libzfs.zfs_get_type(handle) != zfs.ZFS_TYPE_SNAPSHOT:
            return 0

        nvlist = libzfs.zfs_get_user_props(handle)
        name = libzfs.zfs_get_name(handle)

        with gil:

            # Gathering user props
            nvl = NVList(<uintptr_t>nvlist)

            for key, value in nvl.items():
                src = 'NONE'
                if value.get('source'):
                    src = value.pop('source')
                    if src == name:
                        src = PropertySource.LOCAL.name
                    elif src == '$recvd':
                        src = PropertySource.RECEIVED.name
                    else:
                        src = PropertySource.INHERITED.name

                properties[key] = {
                    'value': value.get('value'),
                    'rawvalue': value.get('value'),
                    'source': src,
                    'parsed': value.get('value')
                }

            for prop_name, prop_id in (props if not simple_handle else {}).items():

                with nogil:
                    strncpy(cvalue, '', libzfs.ZFS_MAXPROPLEN + 1)
                    strncpy(crawvalue, '', libzfs.ZFS_MAXPROPLEN + 1)
                    strncpy(csrcstr, '', MAX_DATASET_NAME_LEN + 1)

                    libzfs.zfs_prop_get(
                        handle, prop_id, cvalue, libzfs.ZFS_MAXPROPLEN,
                        &csource, csrcstr, MAX_DATASET_NAME_LEN, False
                    )

                    libzfs.zfs_prop_get(
                        handle, prop_id, crawvalue, libzfs.ZFS_MAXPROPLEN,
                        NULL, NULL, 0, True
                    )

                properties[prop_name] = {
                    'parsed': parse_zfs_prop(prop_name, crawvalue),
                    'rawvalue': crawvalue,
                    'value': cvalue,
                    'source': PropertySource(<int>csource).name
                }

        if holds:
            ret = libzfs.zfs_get_holds(handle, &ptr)

            with gil:
                if ret != 0:
                    snap_data['holds'] = {}
                else:
                    snap_data['holds'] = dict(NVList(<uintptr_t> ptr))

        if mounted:
            ret = libzfs.zfs_is_mounted(handle, &mntpt)

            with gil:
                snap_data['mountpoint'] = mntpt if ret !=0 else None

        with gil:
            if not simple_handle:
                snap_data['properties'] = properties

            snap_data.update({
                'pool': pool,
                'name': name,
                'type': DatasetType.SNAPSHOT.name,
                'snapshot_name': name.split('@')[-1],
                'dataset': name.split('@')[0],
                'id': name
            })

            snap_list.append(snap_data)

        libzfs.zfs_close(handle)

    @staticmethod
    cdef int __datasets_snapshots(libzfs.zfs_handle_t *handle, void *arg) nogil:
        ZFS.__snapshot_details(handle, arg)
        libzfs.zfs_iter_filesystems(handle, ZFS.__datasets_snapshots, arg)
        libzfs.zfs_close(handle)


    def snapshots_serialized(self, props=None, holds=False, mounted=False):
        cdef libzfs.zfs_handle_t* handle
        cdef const char *c_name
        cdef int prop_id

        prop_mapping = {}
        props = props or []

        for prop_id in ZFS.proptypes[DatasetType.SNAPSHOT]:
            with nogil:
                prop_name = libzfs.zfs_prop_to_name(prop_id)

            if not props or prop_name in props:
                prop_mapping[prop_name] = prop_id

        snap_list = [{
            'props': prop_mapping,
            'holds': holds,
            'mounted': mounted
        }]
        for p in self.pools:
            c_name = handle = NULL
            name = p.name
            c_name = name

            snap_list[0]['pool'] = name

            with nogil:
                handle = libzfs.zfs_open(self.handle, c_name, zfs.ZFS_TYPE_FILESYSTEM)
                ZFS.__datasets_snapshots(handle, <void*>snap_list)

        return snap_list[1:]

    property errno:
        def __get__(self):
            return Error(libzfs.libzfs_errno(self.handle))

    property errstr:
        def __get__(self):
            return libzfs.libzfs_error_description(self.handle)

    property pools:
        def __get__(self):
            if self.mnttab_cache_enable:
                with nogil:
                    libzfs.libzfs_mnttab_cache(self.handle, self.mnttab_cache_enable)

            cdef ZFSPool pool
            pools = []

            with nogil:
                libzfs.zpool_iter(self.handle, self.__iterate_pools, <void*>pools)

            for h in pools:
                pool = ZFSPool.__new__(ZFSPool)
                pool.root = self
                pool.handle = <libzfs.zpool_handle_t*><uintptr_t>h
                if pool.name == '$import':
                    continue

                yield pool

            if self.mnttab_cache_enable:
                with nogil:
                    libzfs.libzfs_mnttab_cache(self.handle, False)

    property datasets:
        def __get__(self):
            for p in self.pools:
                try:
                    yield p.root_dataset
                    for c in p.root_dataset.children_recursive:
                        yield c
                except ZFSException:
                    continue

    property snapshots:
        def __get__(self):
            for p in self.pools:
                try:
                    for c in p.root_dataset.snapshots_recursive:
                        yield c
                except ZFSException:
                    continue

    def get(self, name):
        cdef const char *c_name = name
        cdef libzfs.zpool_handle_t* handle = NULL
        cdef ZFSPool pool

        with nogil:
            handle = libzfs.zpool_open_canfail(self.handle, c_name)

        if handle == NULL:
            raise ZFSException(Error.NOENT, 'Pool {0} not found'.format(name))

        pool = ZFSPool.__new__(ZFSPool)
        pool.root = self
        pool.handle = handle
        return pool

    def find_import(self, cachefile=None, name=None, destroyed=False, search_paths=None):
        cdef ZFSImportablePool pool
        cdef libzfs.importargs_t iargs
        cdef char* paths = "/dev"
        cdef char* c_name
        cdef nvpair.nvlist_t* result

        iargs.path = &paths
        iargs.paths = 1
        iargs.poolname = NULL
        iargs.guid = 0
        iargs.cachefile = NULL

        if name:
            encoded = name.encode('utf-8')
            c_name = encoded
            iargs.poolname = c_name

        if search_paths:
            iargs.path = <char **>malloc(len(search_paths) * sizeof(char *))
            iargs.paths = len(search_paths)
            for i, p in enumerate(search_paths):
                iargs.path[i] = <char *>p

        if cachefile:
            iargs.cachefile = cachefile

        with nogil:
            IF HAVE_ZPOOL_SEARCH_IMPORT_LIBZUTIL and HAVE_ZPOOL_SEARCH_IMPORT_PARAMS == 3:
                result = libzfs.zpool_search_import(self.handle, &iargs, &libzfs.libzfs_config_ops)
            ELSE:
                result = libzfs.zpool_search_import(self.handle, &iargs)

        if result is NULL:
            return

        nv = NVList(nvlist=<uintptr_t>result)
        for name, config in nv.items(raw=True):
            pool = ZFSImportablePool.__new__(ZFSImportablePool)
            pool.name = name
            pool.free = False
            pool.nvlist = config

            # Skip destroyed pools
            if config['state'] == PoolState.DESTROYED and not destroyed:
                continue

            yield pool

    def import_pool(self, ZFSImportablePool pool, newname, opts, missing_log=False, any_host=False):
        cdef const char *c_newname = newname
        cdef NVList copts = NVList(otherdict=opts)
        cdef int ret
        cdef int flags = 0
        cdef ZFSPool newpool

        if missing_log:
            flags |= zfs.ZFS_IMPORT_MISSING_LOG

        if any_host:
            flags |= zfs.ZFS_IMPORT_ANY_HOST

        with nogil:
            ret = libzfs.zpool_import_props(
                self.handle,
                pool.nvlist.handle,
                c_newname,
                copts.handle,
                flags
            )

        if ret != 0:
            raise self.get_error()

        newpool = self.get(newname)

        with nogil:
            ret = libzfs.zpool_enable_datasets(newpool.handle, NULL, 0)

        if ret != 0:
            raise self.get_error()

        self.write_history('zpool import', str(pool.guid), newname if newname else pool.name)
        return newpool

    def export_pool(self, ZFSPool pool):
        cdef int ret

        with nogil:
            ret = libzfs.zpool_disable_datasets(pool.handle, True)

        if ret != 0:
            raise self.get_error()

        with nogil:
            ret = libzfs.zpool_export(pool.handle, True, "export")

        if ret != 0:
            raise self.get_error()

        self.write_history('zpool export', str(pool.name))

    def get_dataset(self, name):
        cdef const char *c_name = name
        cdef libzfs.zfs_handle_t* handle = NULL
        cdef ZFSPool pool
        cdef ZFSDataset dataset

        with nogil:
            handle = libzfs.zfs_open(self.handle, c_name, zfs.ZFS_TYPE_FILESYSTEM|zfs.ZFS_TYPE_VOLUME)

        if handle == NULL:
            raise ZFSException(Error.NOENT, 'Dataset {0} not found'.format(name))

        pool = ZFSPool.__new__(ZFSPool)
        pool.root = self
        pool.free = False

        with nogil:
            pool.handle = libzfs.zfs_get_pool_handle(handle)

        dataset = ZFSDataset.__new__(ZFSDataset)
        dataset.root = self
        dataset.pool = pool
        dataset.handle = handle
        return dataset

    def get_snapshot(self, name):
        cdef libzfs.zfs_handle_t* handle = NULL
        cdef ZFSPool pool
        cdef ZFSSnapshot snap
        cdef const char *c_name = name

        with nogil:
            handle = libzfs.zfs_open(self.handle, c_name, zfs.ZFS_TYPE_SNAPSHOT)

        if handle == NULL:
            raise ZFSException(Error.NOENT, 'Snapshot {0} not found'.format(name))

        pool = ZFSPool.__new__(ZFSPool)
        pool.root = self
        pool.free = False

        with nogil:
            pool.handle = libzfs.zfs_get_pool_handle(handle)

        snap = ZFSSnapshot.__new__(ZFSSnapshot)
        snap.root = self
        snap.pool = pool
        snap.handle = handle
        return snap

    def get_object(self, name):
        try:
            return self.get_dataset(name)
        except ZFSException as err:
            if err.code == Error.NOENT:
                return self.get_snapshot(name)

            raise err

    def get_dataset_by_path(self, path):
        cdef libzfs.zfs_handle_t* handle
        cdef char *c_path = path
        cdef zfs.zfs_type_t dataset_type = DatasetType.FILESYSTEM.value

        with nogil:
            handle = libzfs.zfs_path_to_zhandle(self.handle, c_path, dataset_type)

        cdef ZFSPool pool
        cdef ZFSDataset dataset
        if handle == NULL:
            raise ZFSException(Error.NOENT, 'Dataset with path {0} not found'.format(path))

        pool = ZFSPool.__new__(ZFSPool)
        pool.root = self
        pool.free = False

        with nogil:
            pool.handle = libzfs.zfs_get_pool_handle(handle)

        dataset = ZFSDataset.__new__(ZFSDataset)
        dataset.root = self
        dataset.pool = pool
        dataset.handle = handle
        return dataset

    def create(self, name, topology, opts, fsopts, enable_all_feat=True):
        cdef NVList root = self.make_vdev_tree(topology).nvlist
        cdef NVList copts
        cdef NVList cfsopts = NVList(otherdict=fsopts)
        cdef const char *c_name = name
        cdef int ret

        if enable_all_feat:
            opts = opts.copy()
            for i in range(0, zfs.SPA_FEATURES):
                feat = &zfs.spa_feature_table[i]
                opts['feature@{}'.format(feat.fi_uname)] = 'enabled'

        copts = NVList(otherdict=opts)

        with nogil:
            ret = libzfs.zpool_create(
                self.handle,
                c_name,
                root.handle,
                copts.handle,
                cfsopts.handle
            )

        if ret != 0:
            raise ZFSException(self.errno, self.errstr)

        if self.history:
            hopts = self.generate_history_opts(opts, '-o')
            hfsopts = self.generate_history_opts(fsopts, '-O')
            self.write_history(
                'zpool create',
                hopts,
                hfsopts,
                name,
                self.history_vdevs_list(topology)
            )

        return self.get(name)

    def destroy(self, name, force=False):
        cdef libzfs.zpool_handle_t* handle
        cdef const char *c_name = name
        cdef int rv
        cdef boolean_t c_force = force

        with nogil:
            handle = libzfs.zpool_open(self.handle, c_name)

        if handle == NULL:
            raise ZFSException(Error.NOENT, 'Pool {0} not found'.format(name))

        with nogil:
            rv = libzfs.zpool_disable_datasets(handle, c_force)

        if rv != 0:
            raise self.get_error()

        with nogil:
            rv = libzfs.zpool_destroy(handle, "destroy")

        if rv != 0:
            raise ZFSException(self.errno, self.errstr)

    def receive(self, name, fd, force=False, nomount=False, resumable=False, props=None, limitds=None):
        cdef libzfs.libzfs_handle_t *handle = self.handle,
        cdef libzfs.recvflags_t flags;
        cdef NVList props_nvl = None
        cdef NVList limitds_nvl = None
        cdef nvpair.nvlist_t *c_props_nvl = NULL
        cdef nvpair.nvlist_t *c_limitds_nvl = NULL
        cdef const char *c_name = name
        cdef int c_fd = fd
        cdef int ret

        memset(&flags, 0, sizeof(libzfs.recvflags_t))

        if force:
            flags.force = True

        if nomount:
            flags.nomount = True

        IF HAVE_RECVFLAGS_T_RESUMABLE:
            if resumable:
                flags.resumable = True

        IF HAVE_ZFS_RECEIVE == 7:
            if props:
                props_nvl = NVList(otherdict=props)
                c_props_nvl = props_nvl.handle

            if limitds:
                limitds_nvl = NVList(otherdict=limitds)
                c_limitds_nvl = limitds_nvl.handle

            with nogil:
                ret = libzfs.zfs_receive(
                    handle,
                    c_name,
                    &flags,
                    c_fd,
                    c_props_nvl,
                    c_limitds_nvl,
                    NULL
                )
        ELSE:
            if props:
                props_nvl = NVList(otherdict=props)
                c_props_nvl = props_nvl.handle

            with nogil:
                IF HAVE_ZFS_RECEIVE == 6:
                    ret = libzfs.zfs_receive(handle, c_name, c_props_nvl, &flags, c_fd, NULL)
                ELSE:
                    ret = libzfs.zfs_receive(handle, c_name, c_props_nvl, &flags, c_fd)

        if ret not in (0, -2):
            raise self.get_error()

    def write_history(self, *args):
        cdef const char *c_message

        history_message = ""

        def eval_arg(argument):
            if isinstance(argument, str):
                return eval_str(argument)
            if isinstance(argument, dict):
                return eval_dict(argument)
            if isinstance(argument, tuple):
                return eval_tuple(argument)
            if isinstance(argument, list):
                return eval_list(argument)
            if isinstance(argument, ZFSVdev):
                return eval_zfsvdev(argument)

            return str(argument)

        def eval_str(argument):
            return " " + argument

        def eval_dict(argument):
            out = ""
            for tup in arg.items():
                out += eval_arg(tup)
            return out

        def eval_tuple(argument):
            if len(argument) == 2:
                if isinstance(argument[1], str):
                    return " " + str(argument[0]) + '=' + str(argument[1])

            out = ""
            for i in argument:
                out += eval_arg(i)
            return out

        def eval_list(argument):
            out = ""
            for i in argument:
                out += eval_arg(i)
            return out

        def eval_zfsvdev(argument):
            disks = argument.disks
            if len(disks):
                out = " " + str(argument.type)
                for disk in disks:
                    out += " " + disk
                return  out
            else:
                return ""

        if self.history:
            history_message = self.history_prefix
            for arg in args:
                history_message += eval_arg(arg)

            c_message = history_message

            with nogil:
                libzfs.zpool_log_history(self.handle, c_message)

    def generate_history_opts(self, opt_dict, prefix):
        keys = []
        out_dict = {}
        if isinstance(opt_dict, dict):
            for key in opt_dict.keys():
                keys.append(key)

            for key in keys:
                out_dict[prefix + ' ' + key] = opt_dict[key]

        return out_dict

    def history_vdevs_list(self, topology):
        out = []
        if self.history:
            data_vdevs = topology.get('data', None)
            if data_vdevs:
                if data_vdevs[0].type == 'disk':
                    data_vdevs = data_vdevs[0].disks[0]

                out.append(data_vdevs)

            if topology.get('cache', False):
                out.append('cache')
                out.append(topology.get('cache'))

            if topology.get('log', False):
                out.append('log')
                out.append(topology.get('log'))

        return out

    IF HAVE_SENDFLAGS_T_TYPEDEF and HAVE_ZFS_SEND_RESUME:
        def send_resume(self, fd, token, flags=None):
            cdef libzfs.sendflags_t cflags
            cdef int ret, c_fd
            cdef char *c_token = token

            memset(&cflags, 0, cython.sizeof(libzfs.sendflags_t))

            if flags:
                convert_sendflags(flags, &cflags)

            c_fd = fd
            with nogil:
                ret = libzfs.zfs_send_resume(self.handle, &cflags, c_fd, c_token)

            if ret != 0:
                raise ZFSException(self.errno, self.errstr)

    IF HAVE_ZFS_SEND_RESUME_TOKEN_TO_NVLIST:
        def describe_resume_token(self, token):
            cdef nvpair.nvlist_t *nvl
            cdef char *c_token = token

            with nogil:
                nvl = libzfs.zfs_send_resume_token_to_nvlist(self.handle, c_token)

            if nvl == NULL:
                raise ZFSException(self.errno, self.errstr)

            return dict(NVList(<uintptr_t>nvl))


cdef class ZPoolProperty(object):
    cdef int propid
    cdef readonly ZFSPool pool

    def __init__(self):
        raise RuntimeError('ZPoolProperty cannot be instantiated by the user')

    def __getstate__(self):
        return {
            'value': self.value,
            'rawvalue': self.rawvalue,
            'parsed': self.parsed,
            'source': self.source.name
        }

    def __str__(self):
        return "<libzfs.ZPoolProperty name '{0}' value '{1}'>".format(self.name, self.value)

    def __repr__(self):
        return str(self)

    property name:
        def __get__(self):
            return libzfs.zpool_prop_to_name(self.propid)

    property value:
        def __get__(self):
            cdef char cstr[libzfs.ZPOOL_MAXPROPLEN]
            cdef int ret

            with nogil:
                ret = libzfs.zpool_get_prop(self.pool.handle, self.propid, cstr, sizeof(cstr), NULL, False)

            if ret != 0:
                return '-'

            return cstr

        def __set__(self, value):
            cdef const char *c_name
            cdef const char *c_value = value
            cdef int ret

            name = self.name
            c_name = name

            with nogil:
                ret = libzfs.zpool_set_prop(self.pool.handle, c_name, c_value)

            if ret != 0:
                raise self.pool.root.get_error()

            self.pool.root.write_history('zpool set', (self.name, str(value)), self.pool.name)

    property rawvalue:
        def __get__(self):
            cdef char cstr[libzfs.ZPOOL_MAXPROPLEN]
            cdef int ret

            with nogil:
                ret = libzfs.zpool_get_prop(self.pool.handle, self.propid, cstr, sizeof(cstr), NULL, True)

            if ret != 0:
                return '-'

            return cstr

    property source:
        def __get__(self):
            cdef zfs.zprop_source_t src

            with nogil:
                libzfs.zpool_get_prop(self.pool.handle, self.propid, NULL, 0, &src, True)

            return PropertySource(src)

    property parsed:
        def __get__(self):
            return parse_zpool_prop(self.name, self.rawvalue)

        def __set__(self, value):
            self.value = serialize_zpool_prop(self.name, value)

    property allowed_values:
        def __get__(self):
            return libzfs.zfs_prop_values(self.propid)

    def reset(self):
        pass


cdef class ZPoolFeature(object):
    cdef readonly ZFSPool pool
    cdef NVList nvlist
    cdef zfs.zfeature_info_t *feature

    def __getstate__(self):
        return {
            'name': self.name,
            'guid': self.guid,
            'description': self.description,
            'state': self.state.name
        }

    property name:
        def __get__(self):
            return self.feature.fi_uname

    property guid:
        def __get__(self):
            return self.feature.fi_guid

    property description:
        def __get__(self):
            return self.feature.fi_desc

    property state:
        def __get__(self):
            if self.guid not in self.nvlist:
                return FeatureState.DISABLED

            if self.nvlist[self.guid] == 0:
                return FeatureState.ENABLED

            if self.nvlist[self.guid] > 0:
                return FeatureState.ACTIVE

    def enable(self):
        cdef const char *c_name
        cdef int ret

        name = "feature@{0}".format(self.name)
        c_name = name

        with nogil:
            ret = libzfs.zpool_set_prop(self.pool.handle, c_name, "enabled")

        if ret != 0:
            raise self.pool.root.get_error()

        self.pool.root.write_history('zpool set', (self.name, 'enabled'), self.pool.name)


cdef class ZFSProperty(object):
    cdef readonly ZFSObject dataset
    cdef int propid
    cdef const char *cname
    cdef char cvalue[libzfs.ZFS_MAXPROPLEN + 1]
    cdef char crawvalue[libzfs.ZFS_MAXPROPLEN + 1]
    cdef char csrcstr[MAX_DATASET_NAME_LEN + 1]
    cdef zfs.zprop_source_t csource

    def __init__(self):
        raise RuntimeError('ZFSProperty cannot be instantiated by the user')

    def __getstate__(self):
        return {
            'value': self.value,
            'rawvalue': self.rawvalue,
            'parsed': self.parsed,
            'source': self.source.name if self.source else None
        }

    def __str__(self):
        return "<libzfs.ZFSProperty name '{0}' value '{1}'>".format(self.name, self.value)

    def __repr__(self):
        return str(self)

    def refresh(self):
        with nogil:
            self.cname = libzfs.zfs_prop_to_name(self.propid)
            libzfs.zfs_prop_get(
                self.dataset.handle, self.propid, self.cvalue, libzfs.ZFS_MAXPROPLEN,
                &self.csource, self.csrcstr, MAX_DATASET_NAME_LEN,
                False
            )

            libzfs.zfs_prop_get(
                self.dataset.handle, self.propid, self.crawvalue, libzfs.ZFS_MAXPROPLEN,
                NULL, NULL, 0,
                True
            )

    property name:
        def __get__(self):
            return self.cname

    property value:
        def __get__(self):
            return self.cvalue

        def __set__(self, value):
            cdef const char *c_value
            cdef int ret

            str_value = str(value).encode('utf-8')
            c_value = str_value

            with nogil:
                ret = libzfs.zfs_prop_set(self.dataset.handle, self.cname, c_value)

            if ret != 0:
                raise self.dataset.root.get_error()

            self.dataset.root.write_history('zfs set', (self.name, str(value)), self.dataset.name)

    property rawvalue:
        def __get__(self):
            return self.crawvalue

    property source:
        def __get__(self):
            return PropertySource(<int>self.csource)

    property parsed:
        def __get__(self):
            return parse_zfs_prop(self.name, self.rawvalue)

        def __set__(self, value):
            self.value = serialize_zfs_prop(self.name, value)

    property allowed_values:
        def __get__(self):
            return libzfs.zfs_prop_values(self.propid)

    def inherit(self, recursive=False, bint received=False):
        cdef ZFSObject dset
        cdef int ret
        cdef int c_recursive = recursive
        cdef zfs.zfs_prop_t prop

        self.refresh()

        dsets = [self.dataset]
        if recursive:
            dsets.extend(list(self.dataset.children_recursive))
            prop = <zfs.zfs_prop_t>zfs.zfs_name_to_prop(self.cname)

        for d in dsets:
            dset = <ZFSObject>d
            with nogil:
                if c_recursive and prop != zfs.ZPROP_INVAL:
                    IF HAVE_ZFS_PROP_VALID_FOR_TYPE == 3:
                        ret = <int>zfs.zfs_prop_valid_for_type(prop, libzfs.zfs_get_type(dset.handle), 0)
                    ELSE:
                        ret = <int>zfs.zfs_prop_valid_for_type(prop, libzfs.zfs_get_type(dset.handle))
                    if ret != 1:
                        continue
                ret = libzfs.zfs_prop_inherit(dset.handle, self.cname, received)

            if ret != 0:
                raise self.dataset.root.get_error()

        self.dataset.root.write_history('zfs inherit', '-r' if recursive else '', self.dataset.name)


cdef class ZFSUserProperty(ZFSProperty):
    cdef dict values
    cdef readonly name

    def __init__(self, value):
        self.values = {"value": value}

    def __str__(self):
        return "<libzfs.ZFSUserProperty name '{0}' value '{1}'>".format(self.name, self.value)

    def __repr__(self):
        return str(self)

    property value:
        def __get__(self):
            return self.values.get('value')

        def __set__(self, value):
            cdef const char *c_name
            cdef const char *c_value
            cdef int ret

            str_value = str(value).encode('utf-8')
            c_name = self.name
            c_value = str_value

            if self.dataset:
                with nogil:
                    ret = libzfs.zfs_prop_set(self.dataset.handle, c_name, c_value)

                if ret != 0:
                    raise self.dataset.root.get_error()

                self.values['value'] = value

    property rawvalue:
        def __get__(self):
            return self.value

    property source:
        def __get__(self):
            src = self.values.get('source')
            if not src:
                return None

            if src == self.dataset.name:
                return PropertySource.LOCAL

            if src == '$recvd':
                return PropertySource.RECEIVED

            return PropertySource.INHERITED

    def refresh(self):
        cdef ZFSUserProperty userprop
        cdef nvpair.nvlist_t *nvlist

        self.cname = self.name

        with nogil:
            nvlist = libzfs.zfs_get_user_props(self.dataset.handle)

        nvl = NVList(<uintptr_t>nvlist)

        for k, v in nvl.items():
            if k == self.name:
                self.values.update(v)
                break
        else:
            self.values['value'] = None


cdef class ZFSVdevStats(object):
    cdef readonly ZFSVdev vdev
    cdef NVList _nvlist
    cdef zfs.vdev_stat_t *vs;
    cdef uint_t total

    def __getstate__(self):
        state = {
            'timestamp': self.timestamp,
            'read_errors': self.read_errors,
            'write_errors': self.write_errors,
            'checksum_errors': self.checksum_errors,
            'ops': self.ops,
            'bytes': self.bytes,
            'size': self.size,
            'allocated': self.allocated,
            'fragmentation': self.fragmentation,
            'self_healed': self.self_healed
        }
        IF HAVE_ZFS_VDEV_STAT_ASHIFT:
            state.update({
                'configured_ashift': self.configured_ashift,
                'logical_ashift': self.logical_ashift,
                'physical_ashift': self.physical_ashift,
            })
        return state

    property nvlist:
        def __get__(self):
            return self._nvlist

        def __set__(self, value):
            self._nvlist = value
            ret = self._nvlist.nvlist_lookup_uint64_array(
                <nvpair.nvlist_t*>self._nvlist.handle, zfs.ZPOOL_CONFIG_VDEV_STATS, <uint64_t **>&self.vs, &self.total
            )
            if ret != 0:
                raise ZFSVdevStatsException(ret)

    property timestamp:
        def __get__(self):
            return self.vs.vs_timestamp

    property size:
        def __get__(self):
            return self.vs.vs_space

    property allocated:
        def __get__(self):
            return self.vs.vs_alloc

    property read_errors:
        def __get__(self):
            return self.vs.vs_read_errors

    property write_errors:
        def __get__(self):
            return self.vs.vs_write_errors

    property checksum_errors:
        def __get__(self):
            return self.vs.vs_checksum_errors

    property ops:
        def __get__(self):
            return self.vs.vs_ops

    property bytes:
        def __get__(self):
            return self.vs.vs_bytes

    IF HAVE_ZFS_VDEV_STAT_ASHIFT:
        property configured_ashift:
            def __get__(self):
                return self.vs.vs_configured_ashift

        property logical_ashift:
            def __get__(self):
                return self.vs.vs_logical_ashift

        property physical_ashift:
            def __get__(self):
                return self.vs.vs_physical_ashift

    property fragmentation:
        def __get__(self):
            return self.vs.vs_fragmentation

    property self_healed:
        def __get__(self):
            # This is in bytes
            return self.vs.vs_self_healed


cdef class ZFSVdev(object):
    cdef readonly ZFSPool zpool
    cdef readonly ZFS root
    cdef readonly ZFSVdev parent
    cdef readonly object group
    cdef NVList nvlist

    def __init__(self, ZFS root, typ, ZFSPool pool=None):
        self.root = root
        self.zpool = pool
        self.nvlist = NVList()
        self.type = typ

    def __str__(self):
        if self.path:
            return "<libzfs.ZFSVdev type '{0}', path '{1}'>".format(self.type, self.path)

        return "<libzfs.ZFSVdev type '{0}'>".format(self.type)

    def __repr__(self):
        return str(self)

    def __getstate__(self, recursive=True):
        ret = {
            'type': self.type,
            'path': self.path,
            'guid': str(self.guid),
            'status': self.status,
            'stats': self.stats.__getstate__()
        }

        if recursive:
            ret['children'] = [i.__getstate__() for i in self.children]

        return ret

    def add_child_vdev(self, ZFSVdev vdev):
        if zfs.ZPOOL_CONFIG_CHILDREN not in self.nvlist:
            self.nvlist.set(zfs.ZPOOL_CONFIG_CHILDREN, [], nvpair.DATA_TYPE_NVLIST_ARRAY)

        self.nvlist[zfs.ZPOOL_CONFIG_CHILDREN] = self.nvlist.get_raw(zfs.ZPOOL_CONFIG_CHILDREN) + [vdev.nvlist]

    def attach(self, ZFSVdev vdev):
        cdef const char *command = 'zpool attach'
        cdef ZFSVdev root
        cdef int rv

        if self.type not in (zfs.VDEV_TYPE_MIRROR, zfs.VDEV_TYPE_DISK, zfs.VDEV_TYPE_FILE):
            raise ZFSException(Error.NOTSUP, "Can attach disks to mirrors and stripes only")

        if self.type == zfs.VDEV_TYPE_MIRROR:
            first_child = next(self.children)
        else:
            first_child = self

        root = self.root.make_vdev_tree({
            'data': [vdev]
        })

        first_child_path = first_child.path
        new_vdev_path = vdev.path

        cdef const char* c_first_child_path = first_child_path
        cdef const char* c_new_vdev_path = new_vdev_path

        with nogil:
            rv = libzfs.zpool_vdev_attach(
                self.zpool.handle, c_first_child_path, c_new_vdev_path, root.nvlist.handle, 0
            )

        if rv != 0:
            raise self.root.get_error()

        self.root.write_history(command, self.zpool.name, first_child.path, vdev.path)

    def replace(self, ZFSVdev vdev):
        cdef const char *command = 'zpool replace'
        cdef ZFSVdev root
        cdef int rv

        if self.type == zfs.VDEV_TYPE_FILE:
            raise ZFSException(Error.NOTSUP, "Can replace disks only")

        root = self.root.make_vdev_tree({
            'data': [vdev]
        })

        self_path = self.path
        vdev_path = vdev.path

        cdef const char *c_path = self_path
        cdef const char *c_vdev_path = vdev_path

        with nogil:
            rv = libzfs.zpool_vdev_attach(self.zpool.handle, c_path, c_vdev_path, root.nvlist.handle, 1)

        if rv != 0:
            raise self.root.get_error()

        self.root.write_history(command, self.zpool.name, self.path, vdev.path)

    def detach(self):
        cdef const char *command = 'zpool detach'
        cdef int rv
        if self.type not in (zfs.VDEV_TYPE_FILE, zfs.VDEV_TYPE_DISK):
            raise ZFSException(Error.NOTSUP, "Cannot detach virtual vdevs")

        if self.parent.type not in (zfs.VDEV_TYPE_MIRROR, zfs.VDEV_TYPE_SPARE):
            raise ZFSException(Error.NOTSUP, "Can detach disks from mirrors and spares only")

        path = self.path

        cdef const char *c_path = path

        with nogil:
            rv = libzfs.zpool_vdev_detach(self.zpool.handle, c_path)

        if rv != 0:
            raise self.root.get_error()

        self.root.write_history(command, self.zpool.name, self.path)

    def remove(self):
        cdef const char *command = 'zpool remove'
        path = self.path
        cdef const char *c_path = path
        cdef int rv

        with nogil:
            rv = libzfs.zpool_vdev_remove(self.zpool.handle, c_path)

        if rv != 0:
            raise self.root.get_error()

        self.root.write_history(command, self.zpool.name, self.path)

    def offline(self, temporary=False):
        cdef const char *command = 'zpool offline'
        if self.type not in (zfs.VDEV_TYPE_DISK, zfs.VDEV_TYPE_FILE):
            raise ZFSException(Error.NOTSUP, "Can make disks offline only")

        path = self.path
        cdef const char *c_path = path
        cdef int c_temporary = int(temporary)
        cdef int rv

        with nogil:
            rv = libzfs.zpool_vdev_offline(self.zpool.handle, c_path, c_temporary)

        if rv != 0:
            raise self.root.get_error()

        self.root.write_history(command, '-t' if temporary else '',self.zpool.name, self.path)

    def online(self, expand=False):
        cdef const char *command = 'zpool online'
        cdef int flags = 0
        cdef zfs.vdev_state_t newstate

        if self.type not in (zfs.VDEV_TYPE_DISK, zfs.VDEV_TYPE_FILE):
            raise ZFSException(Error.NOTSUP, "Can make disks online only")

        if expand:
            flags |= zfs.ZFS_ONLINE_EXPAND

        path = self.path
        cdef const char *c_path = path
        cdef int rv

        with nogil:
            rv = libzfs.zpool_vdev_online(self.zpool.handle, c_path, flags, &newstate)

        if rv != 0:
            raise self.root.get_error()

        self.root.write_history(command, '-e' if expand else '', self.zpool.name, self.path)

    def degrade(self, aux):
        cdef zfs.vdev_aux_t c_aux = VDevAuxState(int(aux))
        cdef uint64_t c_guid = self.guid
        cdef int rv

        with nogil:
            rv = libzfs.zpool_vdev_degrade(self.zpool.handle, c_guid, c_aux)

        if rv != 0:
            raise self.root.get_error()

    def fault(self, aux):
        cdef zfs.vdev_aux_t c_aux = VDevAuxState(int(aux))
        cdef uint64_t c_guid = self.guid
        cdef int rv

        with nogil:
            rv = libzfs.zpool_vdev_fault(self.zpool.handle, c_guid, c_aux)

        if rv != 0:
            raise self.root.get_error()

    property type:
        def __get__(self):
            value = self.nvlist.get('type')
            if value == zfs.VDEV_TYPE_RAIDZ:
                return value + str(self.nvlist.get('nparity'))

            return value

        def __set__(self, value):
            if value not in (
                zfs.VDEV_TYPE_ROOT,
                zfs.VDEV_TYPE_DISK,
                zfs.VDEV_TYPE_FILE,
                'raidz1',
                'raidz2',
                'raidz3',
                zfs.VDEV_TYPE_MIRROR
            ):
                raise ValueError('Invalid vdev type')

            self.nvlist['type'] = value

            if value.startswith(zfs.VDEV_TYPE_RAIDZ):
                self.nvlist['type'] = zfs.VDEV_TYPE_RAIDZ
                self.nvlist['nparity'] = long(value[-1])

    property guid:
        def __get__(self):
            return self.nvlist.get(zfs.ZPOOL_CONFIG_GUID)

    property path:
        def __get__(self):
            return self.nvlist.get(zfs.ZPOOL_CONFIG_PATH)

        def __set__(self, value):
            self.nvlist[zfs.ZPOOL_CONFIG_PATH] = value

    property status:
        def __get__(self):
            stats = self.nvlist[zfs.ZPOOL_CONFIG_VDEV_STATS]
            return libzfs.zpool_state_to_name(stats[1], stats[2])

    property size:
        def __get__(self):
            return self.nvlist[zfs.ZPOOL_CONFIG_ASIZE] << self.nvlist[zfs.ZPOOL_CONFIG_ASHIFT]

    property stats:
        def __get__(self):
            cdef ZFSVdevStats ret

            ret = ZFSVdevStats.__new__(ZFSVdevStats)
            ret.vdev = self
            ret.nvlist = self.nvlist
            return ret

    property children:
        def __get__(self):
            cdef ZFSVdev vdev

            if zfs.ZPOOL_CONFIG_CHILDREN not in self.nvlist:
                return

            for i in self.nvlist.get_raw(zfs.ZPOOL_CONFIG_CHILDREN):
                vdev = ZFSVdev.__new__(ZFSVdev)
                vdev.nvlist = i
                vdev.zpool = self.zpool
                vdev.root = self.root
                vdev.parent = self
                vdev.group = self.group
                yield vdev

        def __set__(self, value):
            self.nvlist[zfs.ZPOOL_CONFIG_CHILDREN] = [(<ZFSVdev>i).nvlist for i in value]

    property disks:
        def __get__(self):
            try:
                if self.status in ('UNAVAIL', 'OFFLINE'):
                    return []
            except ValueError:
                # status may not be available in user defined ZFSVdev
                pass
            if self.type == zfs.VDEV_TYPE_DISK:
                return [self.path]
            elif self.type == zfs.VDEV_TYPE_FILE:
                return []
            else:
                result = []
                for i in self.children:
                    result += i.disks

                return result


cdef class ZPoolScrub(object):
    cdef readonly ZFS root
    cdef readonly ZFSPool pool
    cdef readonly object stat

    def __init__(self, ZFS root, ZFSPool pool):
        self.root = root
        self.pool = pool
        self.stat = None
        if zfs.ZPOOL_CONFIG_SCAN_STATS in pool.config[zfs.ZPOOL_CONFIG_VDEV_TREE]:
            self.stat = pool.config[zfs.ZPOOL_CONFIG_VDEV_TREE][zfs.ZPOOL_CONFIG_SCAN_STATS]

    property state:
        def __get__(self):
            if not self.stat:
                return None

            return ScanState(self.stat[1])

    property function:
        def __get__(self):
            if not self.stat:
                return None

            return ScanFunction(self.stat[0])

    property start_time:
        def __get__(self):
            if not self.stat:
                return None

            return datetime.fromtimestamp(self.stat[2])

    property end_time:
        def __get__(self):
            if not self.stat or self.state == ScanState.SCANNING:
                return None

            return datetime.fromtimestamp(self.stat[3])

    property bytes_to_scan:
        def __get__(self):
            if not self.stat:
                return None

            return self.stat[4]

    property bytes_scanned:
        def __get__(self):
            if not self.stat:
                return None

            return self.stat[5]

    property total_secs_left:
        def __get__(self):
            if not self.stat or self.state != ScanState.SCANNING:
                return None

            examined = self.bytes_scanned
            total = self.bytes_to_scan
            elapsed = (int(time.time()) - self.stat[10]) or 1
            pass_exam = self.stat[9] or 1
            rate = pass_exam / elapsed
            return int((total - examined) / rate)

    IF HAVE_POOL_SCAN_STAT_T_ISSUED:
        property bytes_issued:
            def __get__(self):
                if not self.stat:
                    return None

                return self.stat[13]

    IF HAVE_POOL_SCAN_STAT_T_PAUSE:
        property pause:
            def __get__(self):
                if not self.stat:
                    return None

                if self.state != ScanState.SCANNING:
                    return None
                if self.stat[11] == 0:
                    return None
                return datetime.fromtimestamp(self.stat[11])

    property errors:
        def __get__(self):
            if not self.stat:
                return None

            return self.stat[8]

    property percentage:
        def __get__(self):
            if not self.stat:
                return None

            if not self.bytes_to_scan:
                return 0

            IF HAVE_POOL_SCAN_STAT_T_ISSUED:
                return (<float>self.bytes_issued / <float>self.bytes_to_scan) * 100
            ELSE:
                return (<float>self.bytes_scanned / <float>self.bytes_to_scan) * 100

    def __getstate__(self):
        state = {
            'function': self.function.name if self.function else None,
            'state': self.state.name if self.stat else None,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'percentage': self.percentage,
            'bytes_to_process': self.bytes_scanned,
            'bytes_processed': self.bytes_to_scan,
            'errors': self.errors,
            'total_secs_left': self.total_secs_left
        }
        if hasattr(self, 'bytes_issued'):
            state['bytes_issued'] = self.bytes_issued
        if hasattr(self, 'pause'):
            state['pause'] = self.pause
        return state


cdef class ZFSPool(object):
    cdef libzfs.zpool_handle_t* handle
    cdef bint free
    cdef readonly ZFS root

    def __cinit__(self):
        self.free = True

    def __init__(self):
        raise RuntimeError('ZFSPool cannot be instantiated by the user')

    def __dealloc__(self):
        if self.free:
            with nogil:
                libzfs.zpool_close(self.handle)

            self.handle = NULL

    def __str__(self):
        return "<libzfs.ZFSPool name '{0}' guid '{1}'>".format(self.name, self.guid)

    def __repr__(self):
        return str(self)

    def __getstate__(self, datasets_recursive=True):
        try:
            root_ds = self.root_dataset.__getstate__(datasets_recursive)
        except (ZFSException, AttributeError):
            root_ds = None

        state = {
            'name': self.name,
            'id': self.name,
            'guid': str(self.guid),
            'hostname': self.hostname,
            'status': self.status,
            'healthy': self.healthy,
            'error_count': self.error_count,
            'root_dataset': root_ds,
            'properties': {k: p.__getstate__() for k, p in self.properties.items()} if self.properties else None,
            'features': [i.__getstate__() for i in self.features] if self.features else None,
            'scan': self.scrub.__getstate__(),
            'root_vdev': self.root_vdev.__getstate__(False),
            'groups': {
                'data': [i.__getstate__() for i in self.data_vdevs if i.type != zfs.VDEV_TYPE_HOLE],
                'log': [i.__getstate__() for i in self.log_vdevs if i.type != zfs.VDEV_TYPE_HOLE],
                'cache': [i.__getstate__() for i in self.cache_vdevs if i.type != zfs.VDEV_TYPE_HOLE],
                'spare': [i.__getstate__() for i in self.spare_vdevs if i.type != zfs.VDEV_TYPE_HOLE]
            },
        }

        if self.handle != NULL:
            state.update({
                'status_code': self.status_code.name,
                'status_detail': self.status_detail
            })

        return state

    @staticmethod
    cdef int __iterate_props(int proptype, void* arg) nogil:
        with gil:
            proptypes = <object>arg
            proptypes.append(proptype)
            return zfs.ZPROP_CONT

    property root_dataset:
        def __get__(self):
            cdef const char *c_name;
            cdef libzfs.zfs_handle_t* handle = NULL
            cdef ZFSDataset dataset

            name = self.name
            c_name = name

            with nogil:
                handle = libzfs.zfs_open(self.root.handle, c_name, zfs.ZFS_TYPE_FILESYSTEM)

            if handle == NULL:
                raise self.root.get_error()

            dataset = ZFSDataset.__new__(ZFSDataset)
            dataset.root = self.root
            dataset.pool = self
            dataset.handle = handle
            return dataset

    property root_vdev:
        def __get__(self):
            cdef ZFSVdev vdev
            cdef NVList vdev_tree = self.get_raw_config().get_raw(zfs.ZPOOL_CONFIG_VDEV_TREE)

            vdev = ZFSVdev.__new__(ZFSVdev)
            vdev.root = self.root
            vdev.zpool = self
            vdev.nvlist = <NVList>vdev_tree
            return vdev

    property data_vdevs:
        def __get__(self):
            cdef ZFSVdev vdev
            cdef NVList vdev_tree = self.get_raw_config().get_raw(zfs.ZPOOL_CONFIG_VDEV_TREE)

            if zfs.ZPOOL_CONFIG_CHILDREN not in vdev_tree:
                return

            for child in vdev_tree.get_raw(zfs.ZPOOL_CONFIG_CHILDREN):
                if not child[zfs.ZPOOL_CONFIG_IS_LOG]:
                    vdev = ZFSVdev.__new__(ZFSVdev)
                    vdev.root = self.root
                    vdev.zpool = self
                    vdev.nvlist = <NVList>child
                    vdev.group = 'data'
                    yield vdev

    property log_vdevs:
        def __get__(self):
            cdef ZFSVdev vdev
            cdef NVList vdev_tree = self.get_raw_config().get_raw(zfs.ZPOOL_CONFIG_VDEV_TREE)

            if zfs.ZPOOL_CONFIG_CHILDREN not in vdev_tree:
                return

            for child in vdev_tree.get_raw(zfs.ZPOOL_CONFIG_CHILDREN):
                if child[zfs.ZPOOL_CONFIG_IS_LOG]:
                    vdev = ZFSVdev.__new__(ZFSVdev)
                    vdev.root = self.root
                    vdev.zpool = self
                    vdev.nvlist = <NVList>child
                    vdev.group = 'log'
                    yield vdev

    property cache_vdevs:
        def __get__(self):
            cdef ZFSVdev vdev
            cdef NVList vdev_tree = self.get_raw_config().get_raw(zfs.ZPOOL_CONFIG_VDEV_TREE)

            if zfs.ZPOOL_CONFIG_L2CACHE not in vdev_tree:
                return

            for child in vdev_tree.get_raw(zfs.ZPOOL_CONFIG_L2CACHE):
                    vdev = ZFSVdev.__new__(ZFSVdev)
                    vdev.root = self.root
                    vdev.zpool = self
                    vdev.nvlist = <NVList>child
                    vdev.group = 'cache'
                    yield vdev

    property spare_vdevs:
        def __get__(self):
            cdef ZFSVdev vdev
            cdef NVList vdev_tree = self.get_raw_config().get_raw(zfs.ZPOOL_CONFIG_VDEV_TREE)

            if zfs.ZPOOL_CONFIG_SPARES not in vdev_tree:
                return

            for child in vdev_tree.get_raw(zfs.ZPOOL_CONFIG_SPARES):
                    vdev = ZFSVdev.__new__(ZFSVdev)
                    vdev.root = self.root
                    vdev.zpool = self
                    vdev.nvlist = <NVList>child
                    vdev.group = 'spare'
                    yield vdev

    property groups:
        def __get__(self):
            return {
                'data': list(self.data_vdevs),
                'log': list(self.log_vdevs),
                'cache': list(self.cache_vdevs),
                'spare': list(self.spare_vdevs)
            }

    property name:
        def __get__(self):
            return libzfs.zpool_get_name(self.handle)

    property guid:
        def __get__(self):
            return self.config[zfs.ZPOOL_CONFIG_POOL_GUID]

    property hostname:
        def __get__(self):
            return self.config.get(zfs.ZPOOL_CONFIG_HOSTNAME)

    property state:
        def __get__(self):
            return PoolState(self.config[zfs.ZPOOL_CONFIG_POOL_STATE])

    property status:
        def __get__(self):
            stats = self.config[zfs.ZPOOL_CONFIG_VDEV_TREE][zfs.ZPOOL_CONFIG_VDEV_STATS]
            return libzfs.zpool_state_to_name(stats[1], stats[2])

    property status_code:
        def __get__(self):
            cdef char* msg_id
            if self.handle != NULL:
                IF HAVE_ZPOOL_GET_STATUS == 3:
                    return PoolStatus(libzfs.zpool_get_status(self.handle, &msg_id, NULL))
                ELSE:
                    return PoolStatus(libzfs.zpool_get_status(self.handle, &msg_id))

    property healthy:
        def __get__(self):
            ok = [
                PoolStatus.OK,
                PoolStatus.VERSION_OLDER,
                PoolStatus.FEAT_DISABLED
            ]

            IF HAVE_ZPOOL_STATUS_NON_NATIVE_ASHIFT:
                ok.append(PoolStatus.NON_NATIVE_ASHIFT)

            return self.status_code in ok

    def __unsup_features(self):
        try:
            nvinfo = self.get_raw_config()[zfs.ZPOOL_CONFIG_LOAD_INFO]
            return dict(nvinfo[zfs.ZPOOL_CONFIG_UNSUP_FEAT])
        except ValueError as e:
            return str(e)

    property status_detail:
        def __get__(self):
            code = self.status_code
            if code is None:
                return None

            status_mapping = {
                PoolStatus.MISSING_DEV_R: 'One or more devices could not be opened. Sufficient replicas exist for '
                                          'the pool to continue functioning in a degraded state.',
                PoolStatus.MISSING_DEV_NR: 'One or more devices could not be opened. There are insufficient '
                                           'replicas for the pool to continue functioning.',
                PoolStatus.CORRUPT_LABEL_R: 'One or more devices could not be used because the label is missing or '
                                            'invalid. Sufficient replicas exist for the pool to continue functioning '
                                            'in a degraded state.',
                PoolStatus.CORRUPT_LABEL_NR: 'One or more devices could not be used because the label is missing '
                                             'or invalid. There are insufficient replicas for the pool to continue '
                                             'functioning.',
                PoolStatus.FAILING_DEV: 'One or more devices has experienced an unrecoverable error. An attempt was '
                                        'made to correct the error. Applications are unaffected.',
                PoolStatus.OFFLINE_DEV: 'One or more devices has been taken offline by the administrator. Sufficient '
                                        'replicas exist for the pool to continue functioning in a degraded state.',
                PoolStatus.REMOVED_DEV: 'One or more devices has been removed by the administrator. Sufficient '
                                        'replicas exist for the pool to continue functioning in a degraded state.',
                PoolStatus.RESILVERING: 'One or more devices is currently being resilvered. The pool will continue '
                                        'to function, possibly in a degraded state.',
                PoolStatus.CORRUPT_DATA: 'One or more devices has experienced an error resulting in data '
                                         'corruption. Applications may be affected.',
                PoolStatus.CORRUPT_POOL: 'The pool metadata is corrupted and the pool cannot be opened.',
                PoolStatus.VERSION_OLDER: 'The pool is formatted using a legacy on-disk format. The pool can still '
                                          'be used, but some features are unavailable.',
                PoolStatus.VERSION_NEWER: 'The pool has been upgraded to a newer, incompatible on-disk version. '
                                          'The pool cannot be accessed on this system.',
                PoolStatus.FEAT_DISABLED: 'Some supported features are not enabled on the pool. The pool can still '
                                          'be used, but some features are unavailable.',
                PoolStatus.UNSUP_FEAT_READ: 'The pool cannot be accessed on this system because it uses the following '
                                            f'feature(s) not supported on this system: {self.__unsup_features()}',
                PoolStatus.UNSUP_FEAT_WRITE: 'The pool can only be accessed in read-only mode on this system. It '
                                             'cannot be accessed in read-write mode because it uses the following '
                                             f'feature(s) not supported on this system: {self.__unsup_features()}',
                PoolStatus.FAULTED_DEV_R: 'One or more devices are faulted in response to persistent errors. '
                                          'Sufficient replicas exist for the pool to continue functioning in a '
                                          'degraded state.',
                PoolStatus.FAULTED_DEV_NR: 'One or more devices are faulted in response to persistent errors. '
                                           'There are insufficient replicas for the pool to continue functioning.',
                PoolStatus.IO_FAILURE_CONTINUE: 'One or more devices are faulted in response to IO failures.',
                PoolStatus.BAD_LOG: 'An intent log record could not be read. Waiting for administrator intervention '
                                    'to fix the faulted pool.'
            }

            IF HAVE_ZPOOL_STATUS_NON_NATIVE_ASHIFT:
                status_mapping[PoolStatus.NON_NATIVE_ASHIFT] = 'One or more devices are configured to use a ' \
                                                               'non-native block size. Expect reduced performance.'

            return status_mapping.get(code.value)

    property error_count:
        def __get__(self):
            return self.config.get(zfs.ZPOOL_CONFIG_ERRCOUNT)

    property config:
        def __get__(self):
            return dict(self.get_raw_config())

    property properties:
        def __get__(self):
            cdef ZPoolProperty prop
            proptypes = []
            result = {}

            with nogil:
                libzfs.zprop_iter(self.__iterate_props, <void*>proptypes, True, True, zfs.ZFS_TYPE_POOL)

            for x in proptypes:
                prop = ZPoolProperty.__new__(ZPoolProperty)
                prop.pool = self
                prop.propid = x
                result[prop.name] = prop

            return result

    property features:
        def __get__(self):
            cdef ZPoolFeature f
            cdef NVList features_nv
            cdef zfs.zfeature_info_t* feat
            cdef uintptr_t nvl

            if self.status == 'UNAVAIL':
                return

            with nogil:
                nvl = <uintptr_t>libzfs.zpool_get_features(self.handle)

            features_nv = NVList(nvl)

            for i in range(0, zfs.SPA_FEATURES):
                feat = &zfs.spa_feature_table[i]
                f = ZPoolFeature.__new__(ZPoolFeature)
                f.feature = feat
                f.pool = self
                f.nvlist = features_nv
                yield f

    property disks:
        def __get__(self):
            result = []
            for g in self.groups.values():
                for v in g:
                    result += v.disks

            return result

    property scrub:
        def __get__(self):
            return ZPoolScrub(self.root, self)

    cdef NVList get_raw_config(self):
        cdef uintptr_t nvl = <uintptr_t>libzfs.zpool_get_config(self.handle, NULL)
        return NVList(nvl)

    def create(self, name, fsopts, fstype=DatasetType.FILESYSTEM, sparse_vol=False, create_ancestors=False):
        cdef NVList cfsopts
        cdef uint64_t vol_reservation, vol_size
        cdef const char *c_name = name
        cdef zfs.zfs_type_t c_fstype = <zfs.zfs_type_t>fstype
        #cdef char[1024] msg
        #cdef nvpair.nvlist_t *nvlist

        # FIXME: for some reason it complains volsize is not valid property for VOLUME
        #nvlist = libzfs.zfs_valid_proplist(self.root.handle, 4, cfsopts.handle, 0, NULL, self.handle, msg)
        #if nvlist == NULL:
        #    raise self.root.get_error()

        # refreservation will not be set correctly if volblocksize is not an integer
        # making change of volsize not work afterwards
        for i in ('volsize', 'volblocksize'):
            if i not in fsopts:
                continue
            value = fsopts[i]
            if isinstance(value, str):
                fsopts[i] = nicestrtonum(self.root, value)

        cfsopts = NVList(otherdict=fsopts)

        if fstype == DatasetType.VOLUME and not sparse_vol:
            vol_size = cfsopts['volsize']
            with nogil:
                IF HAVE_ZVOLSIZE_TO_RESERVATION_PARAMS == 3:
                    vol_reservation = libzfs.zvol_volsize_to_reservation(self.handle, vol_size, cfsopts.handle)
                ELSE:
                    vol_reservation = libzfs.zvol_volsize_to_reservation(vol_size, cfsopts.handle)

            cfsopts['refreservation'] = vol_reservation

        cdef int ret

        if create_ancestors:
            with nogil:
                ret = libzfs.zfs_create_ancestors(
                    self.root.handle,
                    c_name
                )
            if ret != 0:
                raise self.root.get_error()

        with nogil:
            ret = libzfs.zfs_create(
                self.root.handle,
                c_name,
                c_fstype,
                cfsopts.handle
            )

        if ret != 0:
            raise self.root.get_error()

    def attach_vdevs(self, vdevs_tree):
        cdef const char *command = 'zpool add'
        cdef ZFSVdev vd = self.root.make_vdev_tree(vdevs_tree)
        cdef int ret

        with nogil:
            ret = libzfs.zpool_add(self.handle, vd.nvlist.handle)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history(command, self.name, self.root.history_vdevs_list(vdevs_tree))

    def vdev_by_guid(self, guid):
        def search_vdev(vdev, g):
            if vdev.guid == g:
                return vdev

            for i in vdev.children:
                ret = search_vdev(i, g)
                if ret:
                    return ret

            return None

        if guid == self.root_vdev.guid:
            return self.root_vdev

        for g in (self.data_vdevs, self.cache_vdevs, self.log_vdevs, self.spare_vdevs):
            for i in g:
                ret = search_vdev(i, guid)
                if ret:
                    return ret

    def delete(self):
        cdef int ret

        with nogil:
            ret = libzfs.zpool_destroy(self.handle, "destroy")

        if ret != 0:
            raise self.root.get_error()

    def start_scrub(self):
        cdef int ret

        with nogil:
            IF HAVE_ZPOOL_SCAN == 3:
                ret = libzfs.zpool_scan(self.handle, zfs.POOL_SCAN_SCRUB, zfs.POOL_SCRUB_NORMAL)
            ELSE:
                ret = libzfs.zpool_scan(self.handle, zfs.POOL_SCAN_SCRUB)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history('zpool scrub', self.name)

    def stop_scrub(self):
        cdef int ret

        with nogil:
            IF HAVE_ZPOOL_SCAN == 3:
                ret = libzfs.zpool_scan(self.handle, zfs.POOL_SCAN_NONE, zfs.POOL_SCRUB_NORMAL)
            ELSE:
                ret = libzfs.zpool_scan(self.handle, zfs.POOL_SCAN_NONE)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history('zpool scrub -s', self.name)

    def clear(self):
        cdef NVList policy = NVList()
        cdef int ret
        IF HAVE_ZPOOL_LOAD_POLICY_T:
            policy[zfs.ZPOOL_LOAD_REWIND_POLICY] = zfs.ZPOOL_NO_REWIND
        ELIF HAVE_ZPOOL_REWIND_POLICY_T:
            policy[zfs.ZPOOL_REWIND_REQUEST] = zfs.ZPOOL_NO_REWIND

        with nogil:
            ret = libzfs.zpool_clear(self.handle, NULL, policy.handle)

        self.root.write_history('zpool clear', self.name)
        return ret == 0

    def upgrade(self):
        cdef int ret

        with nogil:
            ret = libzfs.zpool_upgrade(self.handle, zfs.SPA_VERSION)

        if ret != 0:
            raise self.root.get_error()

        for i in self.features:
            if i.state == FeatureState.DISABLED:
                i.enable()

        self.root.write_history('zpool upgrade', self.name)


cdef class ZFSImportablePool(ZFSPool):
    cdef NVList nvlist
    cdef public object name

    def __str__(self):
        return "<libzfs.ZFSImportablePool name '{0}' guid '{1}'>".format(self.name, self.guid)

    def __repr__(self):
        return str(self)

    property config:
        def __get__(self):
            return dict(self.nvlist)

    property properties:
        def __get__(self):
            return None

    property root_dataset:
        def __get__(self):
            return None

    property error_count:
        def __get__(self):
            return 0

    property features:
        def __get__(self):
            return None

    cdef NVList get_raw_config(self):
        return self.nvlist

    def create(self, *args, **kwargs):
        raise NotImplementedError()

    def destroy(self, name):
        raise NotImplementedError()

    def attach_vdev(self, vdev):
        raise NotImplementedError()


cdef class ZFSPropertyDict(dict):
    cdef ZFSObject parent
    cdef object props

    def __repr__(self):
        return '{' + ', '.join(["'{0}': {1}".format(k, repr(v)) for k, v in self.items()]) + '}'

    def refresh(self):
        cdef ZFSProperty prop
        cdef ZFSUserProperty userprop
        cdef nvpair.nvlist_t *nvlist

        proptypes = self.parent.root.proptypes[self.parent.type]
        self.props = {}

        with nogil:
            nvlist = libzfs.zfs_get_user_props(self.parent.handle)

        nvl = NVList(<uintptr_t>nvlist)

        for x in proptypes:
            prop = ZFSProperty.__new__(ZFSProperty)
            prop.dataset = self.parent
            prop.propid = x
            prop.refresh()
            self.props[prop.name] = prop

        for k, v in nvl.items():
            userprop = ZFSUserProperty.__new__(ZFSUserProperty)
            userprop.dataset = self.parent
            userprop.name = k
            userprop.values = v
            self.props[userprop.name] = userprop

    def __delitem__(self, key):
        if key not in self.props:
            raise KeyError(key)

        self.props[key].inherit(recursive=True)

    def __getitem__(self, item):
        return self.props[item]

    def __setitem__(self, key, value):
        cdef ZFSUserProperty userprop
        cdef int ret
        cdef const char *c_key
        cdef const char *c_value

        if type(value) is not ZFSUserProperty:
            raise ValueError('Value should be of type ZFSUserProperty')

        userprop = <ZFSUserProperty>value
        if userprop.dataset is None:
            # detached user property
            userprop.dataset = self.parent
            str_value = str(userprop.value).encode('utf-8')
            c_value = str_value
            c_key = key

            with nogil:
                ret = libzfs.zfs_prop_set(self.parent.handle, c_key, c_value)

            if ret != 0:
                raise self.parent.root.get_error()

        self.props[key] = userprop
        self.parent.root.write_history('zfs set', (str(key), str(userprop.value)), self.parent.name)

    def __iter__(self):
        for i in self.props:
            yield  i

    def get(self, k, d=None):
        return self.props.get(k, d)

    def setdefault(self, k, d=None):
        pass

    def keys(self):
        return self.props.keys()

    def values(self):
        return self.props.values()

    def iterkeys(self):
        return self.props.iterkeys()

    def itervalues(self):
        return self.props.itervalues()

    def has_key(self, key):
        return key in self.props

    def items(self):
        return self.props.items()

    def update(self, E=None, **F):
        raise NotImplementedError()

    def __contains__(self, key):
        return key in self.props


cdef class ZFSObject(object):
    cdef libzfs.zfs_handle_t* handle
    cdef readonly ZFS root
    cdef readonly ZFSPool pool

    def __init__(self):
        raise RuntimeError('ZFSObject cannot be instantiated by the user')

    def __dealloc__(self):
        with nogil:
            libzfs.zfs_close(self.handle)

    def __str__(self):
        return "<libzfs.{0} name '{1}' type '{2}'>".format(self.__class__.__name__, self.name, self.type.name)

    def __repr__(self):
        return str(self)

    def __getstate__(self):
        return {
            'id': self.name,
            'name': self.name,
            'pool': self.pool.name,
            'type': self.type.name,
            'properties': {k: p.__getstate__() for k, p in self.properties.items()},
        }

    property name:
        def __get__(self):
            return libzfs.zfs_get_name(self.handle)

    property type:
        def __get__(self):
            cdef zfs.zfs_type_t typ

            with nogil:
                typ = libzfs.zfs_get_type(self.handle)

            return DatasetType(typ)

    property properties:
        def __get__(self):
            cdef ZFSPropertyDict d

            d = ZFSPropertyDict.__new__(ZFSPropertyDict)
            d.parent = self
            d.refresh()
            return d

    def rename(self, new_name, nounmount=False, forceunmount=False, recursive=False):
        cdef const char *c_new_name = new_name
        cdef int ret

        IF HAVE_RENAMEFLAGS_T:
            cdef libzfs.renameflags_t flags
            IF HAVE_RENAMEFLAGS_T_RECURSE:
                flags.recurse = recursive
            ELSE:
                flags.recursive = recursive
            flags.nounmount = nounmount
            flags.forceunmount = forceunmount

            with nogil:
                IF HAVE_ZFS_RENAME == 4:
                    ret = libzfs.zfs_rename(self.handle, NULL, c_new_name, flags)
                ELSE:
                    ret = libzfs.zfs_rename(self.handle, c_new_name, flags)

            history = ['zfs rename', '-f' if forceunmount else '', '-u' if nounmount else '', self.name]

        ELSE:
            if nounmount:
                raise RuntimeError('nounmount option is not supported on this system')

            cdef boolean_t recursive_f = recursive
            cdef boolean_t force_unmount_f = forceunmount

            with nogil:
                ret = libzfs.zfs_rename(self.handle, c_new_name, recursive_f, force_unmount_f)

            history = ['zfs rename', '-f' if forceunmount else '', self.name]

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history(*history)

    def delete(self, bint defer=False):
        cdef int ret

        with nogil:
            ret = libzfs.zfs_destroy(self.handle, defer)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history('zfs destroy', self.name)

    def get_send_space(self, fromname=None):
        cdef const char *cfromname = fromname
        cdef const char *c_name = self.name
        cdef uint64_t space
        cdef int ret

        with nogil:
            IF HAVE_LZC_SEND_SPACE == 4:
                ret = libzfs.lzc_send_space(c_name, cfromname, 0, &space)
            ELSE:
                ret = libzfs.lzc_send_space(c_name, cfromname, &space)

        if ret != 0:
            raise ZFSException(Error.FAULT, "Cannot obtain space estimate: ")

        return space


cdef class ZFSResource(ZFSObject):

    @staticmethod
    cdef int __iterate(libzfs.zfs_handle_t* handle, void *arg) nogil:
        cdef iter_state *iter

        iter = <iter_state *>arg
        if iter.length == iter.alloc:
            iter.alloc += 128
            iter.array = <uintptr_t *>realloc(iter.array, iter.alloc * sizeof(uintptr_t))

        iter.array[iter.length] = <uintptr_t>handle
        iter.length += 1

    def get_dependents(self, allow_recursion=False):
        cdef ZFSDataset dataset
        cdef ZFSSnapshot snapshot
        cdef zfs.zfs_type_t type
        cdef iter_state iter
        cdef int recursion = allow_recursion

        with nogil:
            libzfs.zfs_iter_dependents(self.handle, recursion, self.__iterate, <void*>&iter)

        try:
            for h in range(0, iter.length):
                type = libzfs.zfs_get_type(<libzfs.zfs_handle_t*>iter.array[h])

                if type == zfs.ZFS_TYPE_FILESYSTEM or type == zfs.ZFS_TYPE_VOLUME:
                    dataset = ZFSDataset.__new__(ZFSDataset)
                    dataset.root = self.root
                    dataset.pool = self.pool
                    dataset.handle = <libzfs.zfs_handle_t*>iter.array[h]
                    yield dataset

                if type == zfs.ZFS_TYPE_SNAPSHOT:
                    snapshot = ZFSSnapshot.__new__(ZFSSnapshot)
                    snapshot.root = self.root
                    snapshot.pool = self.pool
                    snapshot.handle = <libzfs.zfs_handle_t*>iter.array[h]
                    yield snapshot
        finally:
            free(iter.array)


cdef class ZFSDataset(ZFSResource):
    def __getstate__(self, recursive=True, snapshots=False, snapshots_recursive=False):
        ret = super(ZFSDataset, self).__getstate__()
        ret['mountpoint'] = self.mountpoint

        if recursive:
            ret['children'] = [i.__getstate__() for i in self.children]

        if snapshots:
            ret['snapshots'] = [s.__getstate__() for s in self.snapshots]

        if snapshots_recursive:
            ret['snapshots_recursive'] = [s.__getstate__() for s in self.snapshots_recursive]

        return ret

    property children:
        def __get__(self):
            cdef ZFSDataset dataset
            cdef iter_state iter

            datasets = []
            with nogil:
                libzfs.zfs_iter_filesystems(self.handle, self.__iterate, <void*>&iter)

            try:
                for h in range(0, iter.length):
                    dataset = ZFSDataset.__new__(ZFSDataset)
                    dataset.root = self.root
                    dataset.pool = self.pool
                    dataset.handle = <libzfs.zfs_handle_t*>iter.array[h]
                    yield dataset
            finally:
                free(iter.array)

    property children_recursive:
        def __get__(self):
            for c in self.children:
                yield c
                for i in c.children_recursive:
                    yield i

    property snapshots:
        def __get__(self):
            cdef ZFSSnapshot snapshot
            cdef iter_state iter

            memset(&iter, 0, sizeof(iter))
            with nogil:
                IF HAVE_ZFS_ITER_SNAPSHOTS == 6:
                    libzfs.zfs_iter_snapshots(self.handle, False, self.__iterate, <void*>&iter, 0, 0)
                ELSE:
                    libzfs.zfs_iter_snapshots(self.handle, False, self.__iterate, <void*>&iter)

            try:
                for h in range(0, iter.length):
                    snapshot = ZFSSnapshot.__new__(ZFSSnapshot)
                    snapshot.root = self.root
                    snapshot.pool = self.pool
                    snapshot.handle = <libzfs.zfs_handle_t*>iter.array[h]
                    if snapshot.snapshot_name == '$ORIGIN':
                        continue

                    yield snapshot
            finally:
                free(iter.array)

    property bookmarks:
        def __get__(self):
            cdef ZFSBookmark bookmark
            cdef iter_state iter

            with nogil:
                libzfs.zfs_iter_bookmarks(self.handle, self.__iterate, <void *>&iter)

            try:
                for b in range(0, iter.length):
                    bookmark = ZFSBookmark.__new__(ZFSBookmark)
                    bookmark.root = self.root
                    bookmark.pool = self.pool
                    bookmark.handle = <libzfs.zfs_handle_t*>iter.array[b]
                    yield bookmark
            finally:
                free(iter.array)

    property snapshots_recursive:
        def __get__(self):
            for s in self.snapshots:
                yield s

            for c in self.children:
                for s in c.snapshots:
                    yield s
                for i in c.children_recursive:
                    for s in i.snapshots:
                        yield s

    property dependents:
        def __get__(self):
            return iter(self.get_dependents(False))

    property mountpoint:
        def __get__(self):
            cdef char *mntpt
            cdef int ret

            with nogil:
                ret = libzfs.zfs_is_mounted(self.handle, &mntpt)

            if ret == 0:
                return None

            result = str(mntpt)
            free(mntpt)
            return result

    def destroy_snapshot(self, name, defer=True):
        cdef const char *c_name = name
        cdef int ret
        cdef int defer_deletion = defer

        with nogil:
            ret = libzfs.zfs_destroy_snaps(self.handle, c_name, defer_deletion)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history('zfs destroy', name)

    def mount(self):
        cdef int ret

        with nogil:
            ret = libzfs.zfs_mount(self.handle, NULL, 0)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history('zfs mount', self.name)

    def mount_recursive(self, ignore_errors=False):
        if self.type != DatasetType.FILESYSTEM:
            return

        if self.properties['canmount'].value == 'on':
            try:
                self.mount()
            except:
                if not ignore_errors:
                    raise

        for i in self.children:
            i.mount_recursive(ignore_errors)

    def umount(self, force=False):
        cdef int flags = 0
        cdef int ret

        if force:
            flags = zfs.MS_FORCE

        with nogil:
            ret = libzfs.zfs_unmountall(self.handle, flags)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history('zfs umount', '-f' if force else '', self.name)

    def umount_recursive(self, force=False):
        if self.type != DatasetType.FILESYSTEM:
            return

        self.umount(force)

        for i in self.children:
            i.umount_recursive(force)

    def send(self, fd, fromname=None, toname=None, flags=None):
        cdef int cfd = fd
        cdef int err
        cdef char *ctoname
        cdef char *cfromname = NULL
        cdef libzfs.sendflags_t cflags

        if isinstance(flags, set) is False:
            flags = set()

        memset(&cflags, 0, cython.sizeof(libzfs.sendflags_t))

        if isinstance(toname, str) is False:
            raise ValueError('toname argument is required')

        ctoname = toname

        if fromname:
            cfromname = fromname

        if flags:
            convert_sendflags(flags, &cflags)

        with nogil:
            err = libzfs.zfs_send(self.handle, cfromname, ctoname, &cflags, cfd, NULL, NULL, NULL)

        if err != 0:
            raise self.root.get_error()

    def get_send_progress(self, fd):
        IF HAVE_ZFS_IOCTL_HEADER:
            cdef zfs.zfs_cmd_t cmd
            memset(&cmd, 0, cython.sizeof(zfs.zfs_cmd_t))

            cdef int ret

            cmd.zc_cookie = fd
            strncpy(cmd.zc_name, self.name, zfs.MAXPATHLEN)

            with nogil:
                ret = libzfs.zfs_ioctl(self.root.handle, zfs.ZFS_IOC_SEND_PROGRESS, &cmd)

            if ret != 0:
                raise ZFSException(Error.FAULT, "Cannot obtain send progress")

            return cmd.zc_cookie
        ELSE:
            raise NotImplementedError()

    def promote(self):
        cdef int ret

        with nogil:
            ret = libzfs.zfs_promote(self.handle)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history('zfs promote', self.name)

    def snapshot(self, name, fsopts=None, recursive=False):
        cdef NVList cfsopts = NVList(otherdict=fsopts or {})
        cdef const char *c_name = name
        cdef int c_recursive = recursive
        cdef int ret

        with nogil:
            ret = libzfs.zfs_snapshot(
                self.root.handle,
                c_name,
                c_recursive,
                cfsopts.handle
            )

        if ret != 0:
            raise self.root.get_error()

        if self.root.history:
            hfsopts = self.root.generate_history_opts(fsopts, '-o')
            self.root.write_history('zfs snapshot', '-r' if recursive else '', hfsopts, name)

    def receive(self, fd, force=False, nomount=False, resumable=False, props=None, limitds=None):
        self.root.receive(
            self.name,
            fd,
            force=force,
            nomount=nomount,
            resumable=resumable,
            props=props,
            limitds=limitds
        )

    def diff(self, fromsnap, tosnap):
        cdef char *c_fromsnap = fromsnap
        cdef char *c_tosnap = tosnap
        cdef int c_flags = libzfs.ZFS_DIFF_PARSEABLE | libzfs.ZFS_DIFF_TIMESTAMP | libzfs.ZFS_DIFF_CLASSIFY
        ret = None

        def worker(fd):
            cdef int c_fd = fd
            cdef int c_ret
            nonlocal ret

            with nogil:
                c_ret = libzfs.zfs_show_diffs(self.handle, c_fd, c_fromsnap, c_tosnap, c_flags)

            ret = c_ret

        rfd, wfd = os.pipe()
        thr = threading.Thread(target=worker, args=(wfd,), daemon=True)
        thr.start()

        with os.fdopen(rfd, 'r') as f:
            for line in f:
                yield DiffRecord(raw=line)

        thr.join()

        if ret != 0:
            raise self.root.get_error()


cdef class ZFSSnapshot(ZFSResource):
    def __getstate__(self):
        ret = super(ZFSSnapshot, self).__getstate__()
        ret.update({
            'holds': self.holds,
            'dataset': self.parent.name,
            'snapshot_name': self.snapshot_name,
            'mountpoint': self.mountpoint
        })
        return ret

    property dependents:
        def __get__(self):
            return iter(self.get_dependents(True))

    def rollback(self, force=False):
        cdef ZFSDataset parent
        cdef int c_force = force
        cdef int ret

        parent = <ZFSDataset>self.parent

        with nogil:
            ret = libzfs.zfs_rollback(parent.handle, self.handle, c_force)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history('zfs rollback', '-f' if force else '', self.name)

    IF HAVE_LZC_BOOKMARK:
        def bookmark(self, name):
            cdef NVList bookmarks
            cdef nvpair.nvlist_t *c_bookmarks
            cdef int ret

            bookmarks = NVList()
            bookmarks['{0}#{1}'.format(self.parent.name, name)] = self.name
            c_bookmarks = bookmarks.handle

            with nogil:
                ret = libzfs.lzc_bookmark(c_bookmarks, NULL)

            if ret != 0:
                raise OSError(ret, os.strerror(ret))

    def clone(self, name, opts=None):
        cdef NVList copts = None
        cdef nvpair.nvlist_t *copts_handle = NULL
        cdef const char *c_name = name
        cdef int ret

        if opts:
            copts = NVList(otherdict=opts)
            copts_handle = copts.handle

        with nogil:
            ret = libzfs.zfs_clone(
                self.handle,
                c_name,
                copts_handle
            )

        if ret != 0:
            raise self.root.get_error()

        if self.root.history:
            hopts = self.root.generate_history_opts(opts, '-o')
            self.root.write_history('zfs clone', hopts, self.name)

    def hold(self, tag, recursive=False):
        cdef ZFSDataset parent
        cdef const char *c_snapshot_name
        cdef const char *c_tag = tag
        cdef int c_recursive = recursive
        cdef int ret

        snapshot_name = self.snapshot_name
        c_snapshot_name = snapshot_name
        parent = <ZFSDataset>self.parent

        with nogil:
            ret = libzfs.zfs_hold(parent.handle, c_snapshot_name, c_tag, c_recursive, -1)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history('zfs hold', '-r' if recursive else '', tag, self.name)

    def release(self, tag, recursive=False):
        cdef ZFSDataset parent
        cdef const char *c_snapshot_name
        cdef const char *c_tag = tag
        cdef int c_recursive = recursive
        cdef int ret

        snapshot_name = self.snapshot_name
        c_snapshot_name = snapshot_name
        parent = <ZFSDataset>self.parent

        with nogil:
            ret = libzfs.zfs_release(parent.handle, c_snapshot_name, c_tag, c_recursive)

        if ret != 0:
            raise self.root.get_error()

        self.root.write_history('zfs release', '-r' if recursive else '', tag, self.name)

    def delete(self, recursive=False, defer=False, recursive_children=False):
        dependents = list(self.dependents)
        if not recursive and not recursive_children:
            if dependents and not defer:
                raise ZFSException(1, f'Cannot destroy {self.name}: snapshot has dependent clones')
            super(ZFSSnapshot, self).delete(defer=defer)
        elif recursive_children:
            for dep in dependents:
                if isinstance(dep, ZFSDataset) and dep.mountpoint:
                    dep.umount(True)
                dep.delete()
            self.delete()
        else:
            self.parent.destroy_snapshot(self.snapshot_name, defer)

        cmd = 'zfs destroy'
        if recursive_children:
            cmd += ' -R'
        elif recursive:
            cmd += ' -r'

        self.root.write_history(cmd, '-d' if defer and not recursive_children else '', self.name)

    def send(self, fd, fromname=None, flags=None):
        if isinstance(flags, set) is False:
            flags = set()
        return self.parent.send(fd, toname=self.snapshot_name, fromname=fromname, flags=flags)

    property snapshot_name:
        def __get__(self):
            return self.name.partition('@')[-1]

    property parent:
        def __get__(self):
            return self.root.get_dataset(self.name.partition('@')[0])

    property holds:
        def __get__(self):
            cdef nvpair.nvlist_t* ptr
            cdef NVList nvl
            cdef int ret

            with nogil:
                ret = libzfs.zfs_get_holds(self.handle, &ptr)

            if ret != 0:
                raise self.root.get_error()

            nvl = NVList(<uintptr_t>ptr)
            return dict(nvl)

    property mountpoint:
        def __get__(self):
            cdef char *mntpt
            cdef int ret

            with nogil:
                ret = libzfs.zfs_is_mounted(self.handle, &mntpt)

            if ret == 0:
                return None

            result = mntpt
            free(mntpt)
            return result

cdef class ZFSBookmark(ZFSObject):
    def __getstate__(self):
        ret = super(ZFSBookmark, self).__getstate__()
        ret.update({
            'dataset': self.parent.name,
            'bookmark_name': self.bookmark_name
        })
        return ret

    property parent:
        def __get__(self):
            return self.root.get_dataset(self.name.partition('#')[0])

    property bookmark_name:
        def __get__(self):
            return self.name.partition('#')[-1]


cdef convert_sendflags(flags, libzfs.sendflags_t *cflags):
    if not isinstance(flags, set):
        raise ValueError('flags must be passed as a set')

    IF HAVE_SENDFLAGS_T_VERBOSITY:
         if SendFlag.VERBOSITY in flags:
            cflags.verbosity = 1
    ELSE:
        if SendFlag.VERBOSE in flags:
            cflags.verbose = 1

    if SendFlag.REPLICATE in flags:
        cflags.replicate = 1

    if SendFlag.DOALL in flags:
        cflags.doall = 1

    if SendFlag.FROMORIGIN in flags:
        cflags.fromorigin = 1

    if SendFlag.DEDUP in flags:
        cflags.dedup = 1

    if SendFlag.PROPS in flags:
        cflags.props = 1

    if SendFlag.DRYRUN in flags:
        cflags.dryrun = 1

    if SendFlag.PARSABLE in flags:
        cflags.parsable = 1

    if SendFlag.PROGRESS in flags:
        cflags.progress = 1

    if SendFlag.LARGEBLOCK in flags:
        cflags.largeblock = 1

    if SendFlag.EMBED_DATA in flags:
        cflags.embed_data = 1

    IF HAVE_SENDFLAGS_T_COMPRESS:
        if SendFlag.COMPRESS in flags:
            cflags.compress = 1


def nicestrtonum(ZFS zfs, value):
    cdef uint64_t result

    if libzfs.zfs_nicestrtonum(zfs.handle, value, &result) != 0:
        raise ValueError('Cannot convert {0} to integer'.format(value))

    return result


def read_label(device):
    cdef nvpair.nvlist_t *handle
    cdef NVList nvlist
    cdef char *buf
    cdef char *read
    cdef int ret

    fd = os.open(device, os.O_RDONLY)
    if fd < 0:
        raise OSError(errno, os.strerror(errno))

    st = os.fstat(fd)
    if not stat.S_ISCHR(st.st_mode):
        os.close(fd)
        raise OSError(errno.EINVAL, 'Not a character device')

    IF HAVE_ZPOOL_READ_LABEL_PARAMS == 3:
        ret = libzfs.zpool_read_label(fd, &handle, NULL)
    ELSE:
        ret = libzfs.zpool_read_label(fd, &handle)

    if ret != 0:
        os.close(fd)
        raise OSError(errno.EINVAL, 'Cannot read label')

    os.close(fd)
    nvlist = NVList(<uintptr_t>handle)
    return dict(nvlist)


def clear_label(device):
    cdef int fd
    cdef int err

    fd = os.open(device, os.O_WRONLY)
    if fd < 0:
        raise OSError(errno, os.strerror(errno))

    with nogil:
        err = libzfs.zpool_clear_label(fd)

    if err != 0:
        os.close(fd)
        raise OSError(errno, os.strerror(errno))

    os.close(fd)
