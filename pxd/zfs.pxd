# encoding: utf-8
# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

include "config.pxi"

from types cimport *


cdef extern from "sys/param.h":
    enum:
        MAXPATHLEN


cdef extern from "sys/mount.h":
    enum:
        MS_FORCE


cdef extern from "sys/fs/zfs.h" nogil:
    # The following are configuration names used in the nvlist describing a pool's configuration
    const char* ZPOOL_CONFIG_VERSION
    const char* ZPOOL_CONFIG_POOL_NAME
    const char* ZPOOL_CONFIG_POOL_STATE
    const char* ZPOOL_CONFIG_POOL_TXG
    const char* ZPOOL_CONFIG_POOL_GUID
    const char* ZPOOL_CONFIG_CREATE_TXG
    const char* ZPOOL_CONFIG_TOP_GUID
    const char* ZPOOL_CONFIG_VDEV_TREE
    const char* ZPOOL_CONFIG_TYPE
    const char* ZPOOL_CONFIG_CHILDREN
    const char* ZPOOL_CONFIG_ID
    const char* ZPOOL_CONFIG_GUID
    const char* ZPOOL_CONFIG_PATH
    const char* ZPOOL_CONFIG_DEVID
    const char* ZPOOL_CONFIG_METASLAB_ARRAY
    const char* ZPOOL_CONFIG_METASLAB_SHIFT
    const char* ZPOOL_CONFIG_ASHIFT
    const char* ZPOOL_CONFIG_ASIZE
    const char* ZPOOL_CONFIG_DTL
    const char* ZPOOL_CONFIG_SCAN_STATS
    const char* ZPOOL_CONFIG_VDEV_STATS
    const char* ZPOOL_CONFIG_WHOLE_DISK
    const char* ZPOOL_CONFIG_ERRCOUNT
    const char* ZPOOL_CONFIG_NOT_PRESENT
    const char* ZPOOL_CONFIG_SPARES
    const char* ZPOOL_CONFIG_IS_SPARE
    const char* ZPOOL_CONFIG_NPARITY
    const char* ZPOOL_CONFIG_HOSTID
    const char* ZPOOL_CONFIG_HOSTNAME
    const char* ZPOOL_CONFIG_LOADED_TIME
    const char* ZPOOL_CONFIG_UNSPARE
    const char* ZPOOL_CONFIG_PHYS_PATH
    const char* ZPOOL_CONFIG_IS_LOG
    const char* ZPOOL_CONFIG_L2CACHE
    const char* ZPOOL_CONFIG_HOLE_ARRAY
    const char* ZPOOL_CONFIG_VDEV_CHILDREN
    const char* ZPOOL_CONFIG_IS_HOLE
    const char* ZPOOL_CONFIG_DDT_HISTOGRAM
    const char* ZPOOL_CONFIG_DDT_OBJ_STATS
    const char* ZPOOL_CONFIG_LOAD_INFO
    const char* ZPOOL_CONFIG_UNSUP_FEAT

    IF HAVE_ZPOOL_CONFIG_ALLOCATION_BIAS:
        const char* ZPOOL_CONFIG_ALLOCATION_BIAS
        const char* VDEV_ALLOC_BIAS_LOG
        const char* VDEV_ALLOC_BIAS_SPECIAL
        const char* VDEV_ALLOC_BIAS_DEDUP

    const char* VDEV_TYPE_ROOT
    const char* VDEV_TYPE_MIRROR
    const char* VDEV_TYPE_REPLACING
    const char* VDEV_TYPE_RAIDZ
    const char* VDEV_TYPE_DISK
    const char* VDEV_TYPE_FILE
    const char* VDEV_TYPE_MISSING
    const char* VDEV_TYPE_HOLE
    const char* VDEV_TYPE_INDIRECT
    const char* VDEV_TYPE_SPARE
    const char* VDEV_TYPE_LOG
    const char* VDEV_TYPE_L2CACHE

    const char* ZFS_DEV

    IF HAVE_ZPOOL_LOAD_POLICY_T:
        # Pool load policy parameter
        const char* ZPOOL_LOAD_POLICY
        const char* ZPOOL_LOAD_REWIND_POLICY
        const char* ZPOOL_LOAD_REQUEST_TXG
        const char* ZPOOL_LOAD_META_THRESH
        const char* ZPOOL_LOAD_DATA_THRESH

    IF HAVE_ZPOOL_REWIND_POLICY_T:
        const char *ZPOOL_REWIND_REQUEST

    IF HAVE_ZPOOL_ERRATA_T_ENUM:
        ctypedef enum zpool_errata_t:
            pass

    IF HAVE_LZC_WAIT:
        ctypedef enum zpool_wait_activity_t:
            ZPOOL_WAIT_CKPT_DISCARD,
            ZPOOL_WAIT_FREE,
            ZPOOL_WAIT_INITIALIZE,
            ZPOOL_WAIT_REPLACE,
            ZPOOL_WAIT_REMOVE,
            ZPOOL_WAIT_RESILVER,
            ZPOOL_WAIT_SCRUB,
            ZPOOL_WAIT_TRIM,
            ZPOOL_WAIT_NUM_ACTIVITIES

    enum:
        ZIO_TYPES
        ZFS_NUM_USERQUOTA_PROPS
        ZFS_NUM_PROPS
        SPA_VERSION

    enum:
        ZAP_MAXNAMELEN
        ZAP_MAXVALUELEN

    enum:
        ZFS_IMPORT_NORMAL
        ZFS_IMPORT_VERBATIM
        ZFS_IMPORT_ANY_HOST
        ZFS_IMPORT_MISSING_LOG
        ZFS_IMPORT_ONLY
        ZFS_ONLINE_EXPAND

    IF HAVE_ZFS_MAX_DATASET_NAME_LEN:
        enum:
            ZFS_MAX_DATASET_NAME_LEN

    ctypedef enum zfs_ioc_t:
        ZFS_IOC_FIRST
        ZFS_IOC_POOL_CREATE
        ZFS_IOC_POOL_DESTROY
        ZFS_IOC_POOL_IMPORT
        ZFS_IOC_POOL_EXPORT
        ZFS_IOC_POOL_CONFIGS
        ZFS_IOC_POOL_STATS
        ZFS_IOC_POOL_TRYIMPORT
        ZFS_IOC_POOL_SCAN
        ZFS_IOC_POOL_FREEZE
        ZFS_IOC_POOL_UPGRADE
        ZFS_IOC_POOL_GET_HISTORY
        ZFS_IOC_VDEV_ADD
        ZFS_IOC_VDEV_REMOVE
        ZFS_IOC_VDEV_SET_STATE
        ZFS_IOC_VDEV_ATTACH
        ZFS_IOC_VDEV_DETACH
        ZFS_IOC_VDEV_SETPATH
        ZFS_IOC_VDEV_SETFRU
        ZFS_IOC_OBJSET_STATS
        ZFS_IOC_OBJSET_ZPLPROPS
        ZFS_IOC_DATASET_LIST_NEXT
        ZFS_IOC_SNAPSHOT_LIST_NEXT
        ZFS_IOC_SET_PROP
        ZFS_IOC_CREATE
        ZFS_IOC_DESTROY
        ZFS_IOC_ROLLBACK
        ZFS_IOC_RENAME
        ZFS_IOC_RECV
        ZFS_IOC_SEND
        ZFS_IOC_INJECT_FAULT
        ZFS_IOC_CLEAR_FAULT
        ZFS_IOC_INJECT_LIST_NEXT
        ZFS_IOC_ERROR_LOG
        ZFS_IOC_CLEAR
        ZFS_IOC_PROMOTE
        ZFS_IOC_DESTROY_SNAPS
        ZFS_IOC_SNAPSHOT
        ZFS_IOC_DSOBJ_TO_DSNAME
        ZFS_IOC_OBJ_TO_PATH
        ZFS_IOC_POOL_SET_PROPS
        ZFS_IOC_POOL_GET_PROPS
        ZFS_IOC_SET_FSACL
        ZFS_IOC_GET_FSACL
        ZFS_IOC_SHARE
        ZFS_IOC_INHERIT_PROP
        ZFS_IOC_SMB_ACL
        ZFS_IOC_USERSPACE_ONE
        ZFS_IOC_USERSPACE_MANY
        ZFS_IOC_USERSPACE_UPGRADE
        ZFS_IOC_HOLD
        ZFS_IOC_RELEASE
        ZFS_IOC_GET_HOLDS
        ZFS_IOC_OBJSET_RECVD_PROPS
        ZFS_IOC_VDEV_SPLIT
        ZFS_IOC_NEXT_OBJ
        ZFS_IOC_DIFF
        ZFS_IOC_TMP_SNAPSHOT
        ZFS_IOC_OBJ_TO_STATS
        ZFS_IOC_JAIL
        ZFS_IOC_UNJAIL
        ZFS_IOC_POOL_REGUID
        ZFS_IOC_SPACE_WRITTEN
        ZFS_IOC_SPACE_SNAPS
        ZFS_IOC_SEND_PROGRESS
        ZFS_IOC_POOL_REOPEN
        ZFS_IOC_LOG_HISTORY
        ZFS_IOC_SEND_NEW
        ZFS_IOC_SEND_SPACE
        ZFS_IOC_CLONE
        ZFS_IOC_BOOKMARK
        ZFS_IOC_GET_BOOKMARKS
        ZFS_IOC_DESTROY_BOOKMARKS
        ZFS_IOC_LAST

    ctypedef enum zfs_type_t:
        ZFS_TYPE_FILESYSTEM	= (1 << 0)
        ZFS_TYPE_SNAPSHOT	= (1 << 1)
        ZFS_TYPE_VOLUME		= (1 << 2)
        ZFS_TYPE_POOL		= (1 << 3)
        ZFS_TYPE_BOOKMARK	= (1 << 4)
    
    ctypedef enum dmu_objset_type_t:
        DMU_OST_NONE
        DMU_OST_META
        DMU_OST_ZFS
        DMU_OST_ZVOL
        DMU_OST_OTHER
        DMU_OST_ANY
        DMU_OST_NUMTYPES

    ctypedef enum zfs_userquota_prop_t:
        ZFS_PROP_USERUSED
        ZFS_PROP_USERQUOTA
        ZFS_PROP_GROUPUSED
        ZFS_PROP_GROUPQUOTA
        ZFS_PROP_USEROBJUSED
        ZFS_PROP_USEROBJQUOTA
        ZFS_PROP_GROUPOBJUSED
        ZFS_PROP_GROUPOBJQUOTA
        ZFS_PROP_PROJECTUSED
        ZFS_PROP_PROJECTQUOTA
        ZFS_PROP_PROJECTOBJUSED
        ZFS_PROP_PROJECTOBJQUOTA
    
    extern const char *zfs_userquota_prop_prefixes[ZFS_NUM_USERQUOTA_PROPS]

    ctypedef enum zprop_source_t:
        ZPROP_SRC_NONE = 0x1
        ZPROP_SRC_DEFAULT = 0x2
        ZPROP_SRC_TEMPORARY = 0x4
        ZPROP_SRC_LOCAL = 0x8
        ZPROP_SRC_INHERITED = 0x10
        ZPROP_SRC_RECEIVED = 0x20
        ZPROP_SRC_ALL = 0x3f

    IF HAVE_ZFS_ENCRYPTION:
        ctypedef enum zfs_keystatus_t:
            ZFS_KEYSTATUS_NONE
            ZFS_KEYSTATUS_UNAVAILABLE
            ZFS_KEYSTATUS_AVAILABLE

    IF HAVE_ZFS_SEND_RESUME_TOKEN_TO_NVLIST:
        IF HAVE_ZFS_ENCRYPTION:
            ctypedef enum zfs_prop_t:
                ZPROP_CONT = -2
                ZPROP_INVAL	= -1
                ZFS_PROP_CANMOUNT
                ZFS_PROP_KEYSTATUS
                ZFS_PROP_RECEIVE_RESUME_TOKEN
                ZFS_PROP_INCONSISTENT
        ELSE:
            ctypedef enum zfs_prop_t:
                ZPROP_CONT = -2
                ZPROP_INVAL	= -1
                ZFS_PROP_CANMOUNT
                ZFS_PROP_RECEIVE_RESUME_TOKEN
                ZFS_PROP_INCONSISTENT
    ELSE:
        IF HAVE_ZFS_ENCRYPTION:
            ctypedef enum zfs_prop_t:
                ZPROP_CONT = -2
                ZPROP_INVAL	= -1
                ZFS_PROP_CANMOUNT
                ZFS_PROP_KEYSTATUS
                ZFS_PROP_INCONSISTENT
        ELSE:
            ctypedef enum zfs_prop_t:
                ZPROP_CONT = -2
                ZPROP_INVAL	= -1
                ZFS_PROP_CANMOUNT
                ZFS_PROP_INCONSISTENT
    
    ctypedef enum zprop_errflags_t:
        ZPROP_ERR_NOCLEAR = 0x1
        ZPROP_ERR_NORESTORE = 0x2
    
    ctypedef int (*zprop_func)(int, void *)
    
    const char *zfs_prop_default_string(int)
    uint64_t zfs_prop_default_numeric(int)
    boolean_t zfs_prop_readonly(int)
    boolean_t zfs_prop_inheritable(int)
    boolean_t zfs_prop_setonce(int)
    const char *zfs_prop_to_name(int)
    int zfs_name_to_prop(const char *)
    boolean_t zfs_prop_user(const char *)
    boolean_t zfs_prop_userquota(const char *)
    int zfs_prop_index_to_string(int, uint64_t, const char **)
    int zfs_prop_string_to_index(int, const char *, uint64_t *)
    uint64_t zfs_prop_random_value(int, uint64_t seed)

    IF HAVE_ZFS_PROP_VALID_FOR_TYPE == 3:
        boolean_t zfs_prop_valid_for_type(int, zfs_type_t, boolean_t)
    ELSE:
        boolean_t zfs_prop_valid_for_type(int, zfs_type_t)

    int zpool_name_to_prop(const char *)
    const char *zpool_prop_to_name(int)
    const char *zpool_prop_default_string(int)
    uint64_t zpool_prop_default_numeric(int)
    boolean_t zpool_prop_readonly(int)
    boolean_t zpool_prop_feature(const char *)
    boolean_t zpool_prop_unsupported(const char *name)
    int zpool_prop_index_to_string(int, uint64_t, const char **)
    int zpool_prop_string_to_index(int, const char *, uint64_t *)
    uint64_t zpool_prop_random_value(int, uint64_t seed)

    ctypedef enum zfs_deleg_who_type_t:
        ZFS_DELEG_WHO_UNKNOWN
        ZFS_DELEG_USER
        ZFS_DELEG_USER_SETS
        ZFS_DELEG_GROUP
        ZFS_DELEG_GROUP_SET
        ZFS_DELEG_EVERYONE
        ZFS_DELEG_EVERYONE_SETS
        ZFS_DELEG_CREATE
        ZFS_DELEG_CREATE_SETS
        ZFS_DELEG_NAMED_SET
        ZFS_DELEG_NAMED_SET_SETS
    
    ctypedef enum zfs_deleg_inherit_t:
        ZFS_DELEG_NONE = 0
        ZFS_DELEG_PERM_LOCAL = 1
        ZFS_DELEG_PERM_DESCENDENT = 2
        ZFS_DELEG_PERM_LOCALDESCENDENT = 3
        ZFS_DELEG_PERM_CREATE = 4
    
    #define	ZFS_DELEG_PERM_UID	"uid"
    #define	ZFS_DELEG_PERM_GID	"gid"
    #define	ZFS_DELEG_PERM_GROUPS	"groups"
    
    #define	ZFS_MLSLABEL_DEFAULT	"none"
    
    #define	ZFS_SMB_ACL_SRC		"src"
    #define	ZFS_SMB_ACL_TARGET	"target"
    
    ctypedef enum zfs_canmount_type_t:
        ZFS_CANMOUNT_OFF = 0
        ZFS_CANMOUNT_ON = 1
        ZFS_CANMOUNT_NOAUTO = 2
    
    ctypedef enum zfs_logbias_op_t:
        ZFS_LOGBIAS_LATENCY = 0
        ZFS_LOGBIAS_THROUGHPUT = 1
    
    ctypedef enum zfs_share_op_t:
        ZFS_SHARE_NFS = 0
        ZFS_UNSHARE_NFS = 1
        ZFS_SHARE_SMB = 2
        ZFS_UNSHARE_SMB = 3
    
    ctypedef enum zfs_smb_acl_op_t:
        ZFS_SMB_ACL_ADD
        ZFS_SMB_ACL_REMOVE
        ZFS_SMB_ACL_RENAME
        ZFS_SMB_ACL_PURGE
    
    ctypedef enum zfs_cache_type_t:
        ZFS_CACHE_NONE = 0
        ZFS_CACHE_METADATA = 1
        ZFS_CACHE_ALL = 2
    
    ctypedef enum zfs_sync_type_t:
        ZFS_SYNC_STANDARD = 0
        ZFS_SYNC_ALWAYS = 1
        ZFS_SYNC_DISABLED = 2
    
    ctypedef enum zfs_volmode_t:
        ZFS_VOLMODE_DEFAULT = 0
        ZFS_VOLMODE_GEOM = 1
        ZFS_VOLMODE_DEV = 2
        ZFS_VOLMODE_NONE = 3
    
    ctypedef enum zfs_redundant_metadata_type_t:
        ZFS_REDUNDANT_METADATA_ALL
        ZFS_REDUNDANT_METADATA_MOST

    enum:
        ZPOOL_NO_REWIND
        ZPOOL_NEVER_REWIND
        ZPOOL_TRY_REWIND
        ZPOOL_DO_REWIN
        ZPOOL_EXTREME_REWIND
        ZPOOL_REWIND_MASK
        ZPOOL_REWIND_POLICIES

    ctypedef struct zpool_rewind_policy_t:
        uint32_t	zrp_request
        uint64_t	zrp_maxmeta
        uint64_t	zrp_maxdata
        uint64_t	zrp_txg

    
    #define	ZPOOL_CONFIG_LOAD_TIME		"rewind_txg_ts"
    #define	ZPOOL_CONFIG_LOAD_DATA_ERRORS	"verify_data_errors"
    #define	ZPOOL_CONFIG_REWIND_TIME	"seconds_of_rewind"

    #define	SPA_MINDEVSIZE		(64ULL << 20)

    #define	ZFS_FRAG_INVALID	UINT64_MAX

    #define	ZPOOL_CACHE		"/boot/zfs/zpool.cache"
    

    ctypedef enum vdev_state_t:
        VDEV_STATE_UNKNOWN = 0
        VDEV_STATE_CLOSED
        VDEV_STATE_OFFLINE
        VDEV_STATE_REMOVED
        VDEV_STATE_CANT_OPEN
        VDEV_STATE_FAULTED
        VDEV_STATE_DEGRADED
        VDEV_STATE_HEALTHY

    IF HAVE_VDEV_AUX_ASHIFT_TOO_BIG:
        ctypedef enum vdev_aux_t:
            VDEV_AUX_NONE
            VDEV_AUX_OPEN_FAILED
            VDEV_AUX_CORRUPT_DATA
            VDEV_AUX_NO_REPLICAS
            VDEV_AUX_BAD_GUID_SUM
            VDEV_AUX_TOO_SMALL
            VDEV_AUX_BAD_LABEL
            VDEV_AUX_VERSION_NEWER
            VDEV_AUX_VERSION_OLDER
            VDEV_AUX_UNSUP_FEAT
            VDEV_AUX_SPARED
            VDEV_AUX_ERR_EXCEEDED
            VDEV_AUX_IO_FAILURE
            VDEV_AUX_BAD_LOG
            VDEV_AUX_EXTERNAL
            VDEV_AUX_SPLIT_POOL
            VDEV_AUX_ASHIFT_TOO_BIG
    ELSE:
        ctypedef enum vdev_aux_t:
            VDEV_AUX_NONE
            VDEV_AUX_OPEN_FAILED
            VDEV_AUX_CORRUPT_DATA
            VDEV_AUX_NO_REPLICAS
            VDEV_AUX_BAD_GUID_SUM
            VDEV_AUX_TOO_SMALL
            VDEV_AUX_BAD_LABEL
            VDEV_AUX_VERSION_NEWER
            VDEV_AUX_VERSION_OLDER
            VDEV_AUX_UNSUP_FEAT
            VDEV_AUX_SPARED
            VDEV_AUX_ERR_EXCEEDED
            VDEV_AUX_IO_FAILURE
            VDEV_AUX_BAD_LOG
            VDEV_AUX_EXTERNAL
            VDEV_AUX_SPLIT_POOL
        
    ctypedef enum pool_state_t:
        POOL_STATE_ACTIVE = 0
        POOL_STATE_EXPORTED
        POOL_STATE_DESTROYED
        POOL_STATE_SPARE
        POOL_STATE_L2CACHE
        POOL_STATE_UNINITIALIZED
        POOL_STATE_UNAVAIL
        POOL_STATE_POTENTIALLY_ACTIVE

    ctypedef enum pool_scan_func_t:
        POOL_SCAN_NONE
        POOL_SCAN_SCRUB
        POOL_SCAN_RESILVER
        POOL_SCAN_FUNCS
        
    IF HAVE_POOL_SCRUB_CMD_T:
        ctypedef enum pool_scrub_cmd_t:
            POOL_SCRUB_NORMAL = 0
            POOL_SCRUB_PAUSE
            POOL_SCRUB_FLAGS_END

    ctypedef enum zio_type_t:
        ZIO_TYPE_NULL = 0
        ZIO_TYPE_READ
        ZIO_TYPE_WRITE
        ZIO_TYPE_FREE
        ZIO_TYPE_CLAIM
        ZIO_TYPE_IOCTL

    ctypedef enum dsl_scan_state_t:
        DSS_NONE
        DSS_SCANNING
        DSS_FINISHED
        DSS_CANCELED
        DSS_NUM_STATES

    ctypedef struct vdev_stat_t:
        hrtime_t	vs_timestamp
        uint64_t	vs_state
        uint64_t	vs_aux
        uint64_t	vs_alloc
        uint64_t	vs_space
        uint64_t	vs_dspace
        uint64_t	vs_rsize
        uint64_t	vs_esize
        uint64_t	vs_ops[ZIO_TYPES]
        uint64_t	vs_bytes[ZIO_TYPES]
        uint64_t	vs_read_errors
        uint64_t	vs_write_errors
        uint64_t	vs_checksum_errors
        uint64_t	vs_self_healed
        uint64_t	vs_scan_removing
        uint64_t	vs_scan_processed
        uint64_t	vs_configured_ashift
        uint64_t	vs_logical_ashift
        uint64_t	vs_physical_ashift
        uint64_t	vs_fragmentation

    ctypedef struct pool_scan_stat_t:
        uint64_t    pss_func # pool_scan_func_t
        uint64_t    pss_state # dsl_scan_state_t
        uint64_t    pss_start_time # scan start time
        uint64_t    pss_end_time # scan end time
        uint64_t    pss_to_examine # total bytes to scan
        uint64_t    pss_examined # total bytes located by scanner
        uint64_t    pss_to_process # total bytes to process
        uint64_t    pss_processed # total processed bytes
        uint64_t    pss_errors # scan errors
        uint64_t    pss_pass_exam # examined bytes per scan pass
        uint64_t    pss_pass_start # start time of a scan pass
        uint64_t    pss_pass_scrub_pause # pause time of a scrub pass
        uint64_t    pss_pass_scrub_spent_paused
        uint64_t    pss_pass_issued # issued bytes per scan pass
        uint64_t    pss_issued # total bytes checked by scanner

    ctypedef struct ddt_object_t:
        uint64_t	ddo_count
        uint64_t	ddo_dspace
        uint64_t	ddo_mspace
    
    ctypedef struct ddt_stat_t:
        uint64_t	dds_blocks
        uint64_t	dds_lsize
        uint64_t	dds_psize
        uint64_t	dds_dsize
        uint64_t	dds_ref_blocks
        uint64_t	dds_ref_lsize
        uint64_t	dds_ref_psize
        uint64_t	dds_ref_dsize
    
    ctypedef struct ddt_histogram_t:
        ddt_stat_t	ddh_stat[64]


IF HAVE_ZFS_IOCTL_HEADER:
    cdef extern from "sys/zfs_ioctl.h":
        ctypedef struct zfs_cmd_t:
            char		zc_name[MAXPATHLEN]
            uint64_t	zc_cookie


cdef extern from "zfeature_common.h":
    ctypedef enum spa_feature_t:
        SPA_FEATURE_NONE
        SPA_FEATURE_ASYNC_DESTROY
        SPA_FEATURE_EMPTY_BPOBJ
        SPA_FEATURE_LZ4_COMPRESS
        SPA_FEATURE_MULTI_VDEV_CRASH_DUMP
        SPA_FEATURE_SPACEMAP_HISTOGRAM
        SPA_FEATURE_ENABLED_TXG
        SPA_FEATURE_HOLE_BIRTH
        SPA_FEATURE_EXTENSIBLE_DATASET
        SPA_FEATURE_EMBEDDED_DATA
        SPA_FEATURE_BOOKMARKS
        SPA_FEATURE_FS_SS_LIMIT
        SPA_FEATURE_LARGE_BLOCKS
        SPA_FEATURES

    ctypedef enum zfeature_flags_t:
        ZFEATURE_FLAG_READONLY_COMPAT
        ZFEATURE_FLAG_MOS
        ZFEATURE_FLAG_ACTIVATE_ON_ENABLE
        ZFEATURE_FLAG_PER_DATASET

    ctypedef struct zfeature_info_t:
        spa_feature_t fi_feature
        const char* fi_uname
        const char* fi_guid
        const char* fi_desc
        zfeature_flags_t fi_flags
        const spa_feature_t* fi_depends

    cdef zfeature_info_t* spa_feature_table
