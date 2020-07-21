# encoding: utf-8
# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

include "config.pxi"

cimport nvpair
cimport zfs
from types cimport *


cdef extern from "libzfs_core.h" nogil:
    IF HAVE_LZC_SEND_SPACE == 4:
        extern int lzc_send_space(const char *, const char *, int, uint64_t *)
    ELSE:
        extern int lzc_send_space(const char *, const char *, uint64_t *)

    enum lzc_send_flags:
            LZC_SEND_FLAG_EMBED_DATA
    IF HAVE_LZC_BOOKMARK:
        extern int lzc_bookmark(nvpair.nvlist_t *bookmarks, nvpair.nvlist_t **errlist)


IF HAVE_LIBZUTIL_HEADER:
    cdef extern from 'libzutil.h' nogil:

        ctypedef struct pool_config_ops_t:
            pass

        extern const pool_config_ops_t libzfs_config_ops;

        IF HAVE_ZPOOL_READ_LABEL_LIBZUTIL and HAVE_ZPOOL_READ_LABEL_PARAMS == 3:
            extern int zpool_read_label(int, nvpair.nvlist_t **, int *)

        IF HAVE_ZPOOL_SEARCH_IMPORT_LIBZUTIL and HAVE_ZPOOL_SEARCH_IMPORT_PARAMS == 3:
            extern nvpair.nvlist_t *zpool_search_import(void *, importargs_t *, const pool_config_ops_t *)


cdef extern from "libzfs.h" nogil:
    cdef enum:
        MAXNAMELEN
        MAXPATHLEN

    IF HAVE_ZFS_MAXNAMELEN or HAVE_ZPOOL_MAXNAMELEN:
        cdef enum:
            ZFS_MAXNAMELEN
            ZPOOL_MAXNAMELEN

    IF HAVE_EZFS_SCRUB_PAUSED:
        cdef enum:
            EZFS_SCRUB_PAUSED

    enum:
        ZFS_MAXPROPLEN
        ZPOOL_MAXPROPLEN

    enum:
        EZFS_SUCCESS = 0
        EZFS_NOMEM = 2000
        EZFS_BADPROP
        EZFS_PROPREADONLY
        EZFS_PROPTYPE
        EZFS_PROPNONINHERIT
        EZFS_PROPSPACE	
        EZFS_BADTYPE	
        EZFS_BUSY	
        EZFS_EXISTS	
        EZFS_NOENT	
        EZFS_BADSTREAM	
        EZFS_DSREADONLY
        EZFS_VOLTOOBIG	
        EZFS_INVALIDNAME
        EZFS_BADRESTORE
        EZFS_BADBACKUP	
        EZFS_BADTARGET	
        EZFS_NODEVICE	
        EZFS_BADDEV	
        EZFS_NOREPLICAS
        EZFS_RESILVERING
        EZFS_BADVERSION
        EZFS_POOLUNAVAIL
        EZFS_DEVOVERFLOW
        EZFS_BADPATH	
        EZFS_CROSSTARGET
        EZFS_ZONED	
        EZFS_MOUNTFAILED
        EZFS_UMOUNTFAILED
        EZFS_UNSHARENFSFAILED
        EZFS_SHARENFSFAILED
        EZFS_PERM	
        EZFS_NOSPC	
        EZFS_FAULT	
        EZFS_IO	
        EZFS_INTR	
        EZFS_ISSPARE	
        EZFS_INVALCONFIG
        EZFS_RECURSIVE	
        EZFS_NOHISTORY	
        EZFS_POOLPROPS	
        EZFS_POOL_NOTSUP
        EZFS_POOL_INVALARG
        EZFS_NAMETOOLONG
        EZFS_OPENFAILED
        EZFS_NOCAP	
        EZFS_LABELFAILED
        EZFS_BADWHO	
        EZFS_BADPERM	
        EZFS_BADPERMSET
        EZFS_NODELEGATION
        EZFS_UNSHARESMBFAILED
        EZFS_SHARESMBFAILED
        EZFS_BADCACHE	
        EZFS_ISL2CACHE	
        EZFS_VDEVNOTSUP
        EZFS_NOTSUP	
        EZFS_ACTIVE_SPARE
        EZFS_UNPLAYED_LOGS
        EZFS_REFTAG_RELE
        EZFS_REFTAG_HOLD
        EZFS_TAGTOOLONG
        EZFS_PIPEFAILED
        EZFS_THREADCREATEFAILED
        EZFS_POSTSPLIT_ONLINE
        EZFS_SCRUBBING
        EZFS_NO_SCRUB
        EZFS_DIFF
        EZFS_DIFFDATA
        EZFS_POOLREADONLY
        EZFS_UNKNOWN

    IF HAVE_ZFS_ENCRYPTION:
        enum:
            EZFS_CRYPTOFAILED

    ctypedef struct libzfs_handle_t:
        pass

    ctypedef struct zpool_handle_t:
        pass

    ctypedef struct zfs_handle_t:
        pass

    extern libzfs_handle_t *libzfs_init()
    extern void libzfs_fini(libzfs_handle_t *)

    extern libzfs_handle_t *zpool_get_handle(zpool_handle_t *)
    extern libzfs_handle_t *zfs_get_handle(zfs_handle_t *)

    extern void libzfs_print_on_error(libzfs_handle_t *, int)

    extern void zfs_save_arguments(int argc, char **, char *, int)
    extern int zpool_log_history(libzfs_handle_t *, const char *)

    extern int libzfs_errno(libzfs_handle_t *)
    extern const char *libzfs_error_action(libzfs_handle_t *)
    extern const char *libzfs_error_description(libzfs_handle_t *)
    extern int zfs_standard_error(libzfs_handle_t *, int, const char *)
    extern void libzfs_mnttab_init(libzfs_handle_t *)
    extern void libzfs_mnttab_fini(libzfs_handle_t *)
    extern void libzfs_mnttab_cache(libzfs_handle_t *, int)
    extern void libzfs_mnttab_add(libzfs_handle_t *, const char *,
        const char *, const char *)
    extern void libzfs_mnttab_remove(libzfs_handle_t *, const char *)
    extern zpool_handle_t *zpool_open(libzfs_handle_t *, const char *)
    extern zpool_handle_t *zpool_open_canfail(libzfs_handle_t *, const char *)
    extern void zpool_close(zpool_handle_t *)
    extern const char *zpool_get_name(zpool_handle_t *)
    extern int zpool_get_state(zpool_handle_t *)
    extern const char *zpool_state_to_name(zfs.vdev_state_t, zfs.vdev_aux_t)
    extern const char *zpool_pool_state_to_name(pool_state_t)
    extern void zpool_free_handles(libzfs_handle_t *)
    ctypedef int (*zpool_iter_f)(zpool_handle_t *, void *)
    extern int zpool_iter(libzfs_handle_t *, zpool_iter_f, void *)
    extern int zpool_create(libzfs_handle_t *, const char *, nvpair.nvlist_t *,
        nvpair.nvlist_t *, nvpair.nvlist_t *)
    extern int zpool_destroy(zpool_handle_t *, const char *)
    extern int zpool_add(zpool_handle_t *, nvpair.nvlist_t *)

    IF HAVE_ZPOOL_SCAN == 3:
        extern int zpool_scan(zpool_handle_t *, zfs.pool_scan_func_t, zfs.pool_scrub_cmd_t)
    ELSE:
        extern int zpool_scan(zpool_handle_t *, zfs.pool_scan_func_t)

    extern int zpool_clear(zpool_handle_t *, const char *, nvpair.nvlist_t *)
    extern int zpool_reguid(zpool_handle_t *)
    extern int zpool_reopen(zpool_handle_t *)

    extern int zpool_vdev_online(zpool_handle_t *, const char *, int,
        zfs.vdev_state_t *)
    extern int zpool_vdev_offline(zpool_handle_t *, const char *, int)
    IF HAVE_ZPOOL_VDEV_ATTACH == 5:
        extern int zpool_vdev_attach(zpool_handle_t *, const char *, const char *, nvpair.nvlist_t *, int)
    ELSE:
        extern int zpool_vdev_attach(zpool_handle_t *, const char *, const char *, nvpair.nvlist_t *, int, boolean_t)
    extern int zpool_vdev_detach(zpool_handle_t *, const char *)
    extern int zpool_vdev_remove(zpool_handle_t *, const char *)

    extern int zpool_vdev_fault(zpool_handle_t *, uint64_t, zfs.vdev_aux_t)
    extern int zpool_vdev_degrade(zpool_handle_t *, uint64_t, zfs.vdev_aux_t)
    extern int zpool_vdev_clear(zpool_handle_t *, uint64_t)

    extern nvpair.nvlist_t *zpool_find_vdev(zpool_handle_t *, const char *, int *,
        int *, int *)
    extern nvpair.nvlist_t *zpool_find_vdev_by_physpath(zpool_handle_t *, const char *,
        int *, int *, int *)
    extern int zpool_label_disk(libzfs_handle_t *, zpool_handle_t *, const char *)

    extern int zpool_set_prop(zpool_handle_t *, const char *, const char *)
    extern int zpool_get_prop(zpool_handle_t *, int prop, char *,
        size_t proplen, zfs.zprop_source_t *, int)
    extern uint64_t zpool_get_prop_int(zpool_handle_t *, int prop,
        zfs.zprop_source_t *)

    extern const char *zpool_prop_to_name(int prop)
    extern const char *zpool_prop_values(int prop)

    IF HAVE_ZPOOL_EVENTS_NEXT:
        extern int zpool_events_next(libzfs_handle_t *, nvpair.nvlist_t **, int *, unsigned, int);

    IF HAVE_ZPOOL_STATUS_NON_NATIVE_ASHIFT:
        ctypedef enum zpool_status_t:
            ZPOOL_STATUS_CORRUPT_CACHE
            ZPOOL_STATUS_MISSING_DEV_R
            ZPOOL_STATUS_MISSING_DEV_NR
            ZPOOL_STATUS_CORRUPT_LABEL_R
            ZPOOL_STATUS_CORRUPT_LABEL_NR
            ZPOOL_STATUS_BAD_GUID_SUM
            ZPOOL_STATUS_CORRUPT_POOL
            ZPOOL_STATUS_CORRUPT_DATA
            ZPOOL_STATUS_FAILING_DEV
            ZPOOL_STATUS_VERSION_NEWER
            ZPOOL_STATUS_HOSTID_MISMATCH
            ZPOOL_STATUS_IO_FAILURE_WAIT
            ZPOOL_STATUS_IO_FAILURE_CONTINUE
            ZPOOL_STATUS_BAD_LOG
            ZPOOL_STATUS_UNSUP_FEAT_READ
            ZPOOL_STATUS_UNSUP_FEAT_WRITE
            ZPOOL_STATUS_FAULTED_DEV_R
            ZPOOL_STATUS_FAULTED_DEV_NR
            ZPOOL_STATUS_VERSION_OLDER
            ZPOOL_STATUS_FEAT_DISABLED
            ZPOOL_STATUS_RESILVERING
            ZPOOL_STATUS_OFFLINE_DEV
            ZPOOL_STATUS_REMOVED_DEV
            ZPOOL_STATUS_NON_NATIVE_ASHIFT
            ZPOOL_STATUS_OK
    ELSE:
        ctypedef enum zpool_status_t:
            ZPOOL_STATUS_CORRUPT_CACHE
            ZPOOL_STATUS_MISSING_DEV_R
            ZPOOL_STATUS_MISSING_DEV_NR
            ZPOOL_STATUS_CORRUPT_LABEL_R
            ZPOOL_STATUS_CORRUPT_LABEL_NR
            ZPOOL_STATUS_BAD_GUID_SUM
            ZPOOL_STATUS_CORRUPT_POOL
            ZPOOL_STATUS_CORRUPT_DATA
            ZPOOL_STATUS_FAILING_DEV
            ZPOOL_STATUS_VERSION_NEWER
            ZPOOL_STATUS_HOSTID_MISMATCH
            ZPOOL_STATUS_IO_FAILURE_WAIT
            ZPOOL_STATUS_IO_FAILURE_CONTINUE
            ZPOOL_STATUS_BAD_LOG
            ZPOOL_STATUS_UNSUP_FEAT_READ
            ZPOOL_STATUS_UNSUP_FEAT_WRITE
            ZPOOL_STATUS_FAULTED_DEV_R
            ZPOOL_STATUS_FAULTED_DEV_NR
            ZPOOL_STATUS_VERSION_OLDER
            ZPOOL_STATUS_FEAT_DISABLED
            ZPOOL_STATUS_RESILVERING
            ZPOOL_STATUS_OFFLINE_DEV
            ZPOOL_STATUS_REMOVED_DEV
            ZPOOL_STATUS_OK

    IF HAVE_ZPOOL_GET_STATUS == 3 and HAVE_ZPOOL_ERRATA_T_ENUM:
        extern zpool_status_t zpool_get_status(zpool_handle_t *, char **, zfs.zpool_errata_t *)
    ELSE:
        extern zpool_status_t zpool_get_status(zpool_handle_t *, char **)

    extern zpool_status_t zpool_import_status(nvpair.nvlist_t *, char **)
    extern void zpool_dump_ddt(const zfs.ddt_stat_t *dds, const zfs.ddt_histogram_t *ddh)
    extern nvpair.nvlist_t *zpool_get_config(zpool_handle_t *, nvpair.nvlist_t **)
    extern nvpair.nvlist_t *zpool_get_features(zpool_handle_t *)
    extern int zpool_refresh_stats(zpool_handle_t *, int *)
    extern int zpool_get_errlog(zpool_handle_t *, nvpair.nvlist_t **)
    extern int zpool_export(zpool_handle_t *, int, const char *)
    extern int zpool_export_force(zpool_handle_t *, const char *)
    extern int zpool_import(libzfs_handle_t *, nvpair.nvlist_t *, const char *,
        char *altroot)
    extern int zpool_import_props(libzfs_handle_t *, nvpair.nvlist_t *, const char *,
        nvpair.nvlist_t *, int)
    extern void zpool_print_unsup_feat(nvpair.nvlist_t *config)

    ctypedef struct importargs_t:
        char **path
        int paths
        char *poolname
        uint64_t guid
        char *cachefile
        int can_be_active
        int unique
        int exists

    IF HAVE_ZPOOL_SEARCH_IMPORT_LIBZFS and HAVE_ZPOOL_SEARCH_IMPORT_PARAMS == 2:
        extern nvpair.nvlist_t *zpool_search_import(libzfs_handle_t *, importargs_t *)

    extern nvpair.nvlist_t *zpool_find_import(libzfs_handle_t *, int, char **)
    extern nvpair.nvlist_t *zpool_find_import_cached(libzfs_handle_t *, const char *,
        char *, uint64_t)

    extern const char *zfs_history_event_names[]

    extern char *zpool_vdev_name(libzfs_handle_t *, zpool_handle_t *, nvpair.nvlist_t *,
        int verbose)
    extern int zpool_upgrade(zpool_handle_t *, uint64_t)
    extern int zpool_history_unpack(char *, uint64_t, uint64_t *,
        nvpair.nvlist_t ***, uint_t *)
    extern void zpool_obj_to_path(zpool_handle_t *, uint64_t, uint64_t, char *,
        size_t len)
    extern int zpool_get_physpath(zpool_handle_t *, char *, size_t)
    extern void zpool_explain_recover(libzfs_handle_t *, const char *, int,
        nvpair.nvlist_t *)

    extern zfs_handle_t *zfs_open(libzfs_handle_t *, const char *, int)
    extern zfs_handle_t *zfs_handle_dup(zfs_handle_t *)
    extern void zfs_close(zfs_handle_t *)
    extern zfs.zfs_type_t zfs_get_type(const zfs_handle_t *)
    extern const char *zfs_get_name(const zfs_handle_t *)
    extern zpool_handle_t *zfs_get_pool_handle(const zfs_handle_t *)

    extern const char *zfs_prop_default_string(int prop)
    extern uint64_t zfs_prop_default_numeric(int prop)
    extern const char *zfs_prop_column_name(int prop)
    extern int zfs_prop_align_right(int prop)

    extern nvpair.nvlist_t *zfs_valid_proplist(libzfs_handle_t *, zfs_type_t,
        nvpair.nvlist_t *, uint64_t, zfs_handle_t *, const char *)

    extern const char *zfs_prop_to_name(int prop)
    extern int zfs_prop_set(zfs_handle_t *, const char *, const char *)
    extern int zfs_prop_get(zfs_handle_t *, int prop, char *, size_t,
        zfs.zprop_source_t *, char *, size_t, int)
    extern int zfs_prop_get_recvd(zfs_handle_t *, const char *, char *, size_t,
        int)
    extern int zfs_prop_get_numeric(zfs_handle_t *, int prop, uint64_t *,
        zfs.zprop_source_t *, char *, size_t)
    extern int zfs_prop_get_userquota_int(zfs_handle_t *zhp, const char *propname,
        uint64_t *propvalue)
    extern int zfs_prop_get_userquota(zfs_handle_t *zhp, const char *propname,
        char *propbuf, int proplen, int literal)
    extern int zfs_prop_get_written_int(zfs_handle_t *zhp, const char *propname,
        uint64_t *propvalue)
    extern int zfs_prop_get_written(zfs_handle_t *zhp, const char *propname,
        char *propbuf, int proplen, int literal)
    extern int zfs_prop_get_feature(zfs_handle_t *zhp, const char *propname,
        char *buf, size_t len)
    extern uint64_t zfs_prop_get_int(zfs_handle_t *, int prop)
    extern int zfs_prop_inherit(zfs_handle_t *, const char *, int)
    extern const char *zfs_prop_values(int prop)
    extern int zfs_prop_is_string(int prop)
    extern nvpair.nvlist_t *zfs_get_user_props(zfs_handle_t *)
    extern nvpair.nvlist_t *zfs_get_recvd_props(zfs_handle_t *)
    extern nvpair.nvlist_t *zfs_get_clones_nvl(zfs_handle_t *)

    ctypedef struct zprop_list_t:
        int		pl_prop
        char		*pl_user_prop
        zprop_list_t *pl_next
        int	pl_all
        size_t		pl_width
        size_t		pl_recvd_width
        int	pl_fixed

    extern int zfs_expand_proplist(zfs_handle_t *, zprop_list_t **, int,
        int)
    extern void zfs_prune_proplist(zfs_handle_t *, uint8_t *)

    extern int zpool_expand_proplist(zpool_handle_t *, zprop_list_t **)
    extern int zpool_prop_get_feature(zpool_handle_t *, const char *, char *,
        size_t)
    extern const char *zpool_prop_default_string(int prop)
    extern uint64_t zpool_prop_default_numeric(int prop)
    extern const char *zpool_prop_column_name(int prop)
    extern int zpool_prop_align_right(int prop)

    extern int zprop_iter(zfs.zprop_func func, void *cb, int show_all,
        int ordered, zfs.zfs_type_t type)
    extern int zprop_get_list(libzfs_handle_t *, char *, zprop_list_t **,
        zfs_type_t)
    extern void zprop_free_list(zprop_list_t *)

    enum:
        ZFS_GET_NCOLS

    ctypedef enum zfs_get_column_t:
        GET_COL_NONE
        GET_COL_NAME
        GET_COL_PROPERTY
        GET_COL_VALUE
        GET_COL_RECVD
        GET_COL_SOURCE

    ctypedef struct zprop_get_cbdata_t:
        int cb_sources
        zfs_get_column_t cb_columns[ZFS_GET_NCOLS]
        int cb_colwidths[ZFS_GET_NCOLS + 1]
        int cb_scripted
        int cb_literal
        int cb_first
        zprop_list_t *cb_proplist
        zfs.zfs_type_t cb_type

    void zprop_print_one_property(const char *, zprop_get_cbdata_t *,
        const char *, const char *, zprop_source_t, const char *,
        const char *)

    ctypedef int (*zfs_iter_f)(zfs_handle_t *, void *)
    extern int zfs_iter_root(libzfs_handle_t *, zfs_iter_f, void *)
    extern int zfs_iter_children(zfs_handle_t *, zfs_iter_f, void *)
    extern int zfs_iter_dependents(zfs_handle_t *, int, zfs_iter_f, void *)
    extern int zfs_iter_filesystems(zfs_handle_t *, zfs_iter_f, void *)
    extern int zfs_iter_snapshots_sorted(zfs_handle_t *, zfs_iter_f, void *)
    extern int zfs_iter_snapspec(zfs_handle_t *, const char *, zfs_iter_f, void *)
    extern int zfs_iter_bookmarks(zfs_handle_t *, zfs_iter_f, void *)

    IF HAVE_ZFS_ITER_SNAPSHOTS == 6:
        extern int zfs_iter_snapshots(zfs_handle_t *, int, zfs_iter_f, void *, uint64_t, uint64_t)
    ELSE:
        extern int zfs_iter_snapshots(zfs_handle_t *, int, zfs_iter_f, void *)

    ctypedef struct get_all_cb_t:
        zfs_handle_t	**cb_handles
        size_t		cb_alloc
        size_t		cb_used
        int	cb_verbose
        int		(*cb_getone)(zfs_handle_t *, void *)


    void libzfs_add_handle(get_all_cb_t *, zfs_handle_t *)
    int libzfs_dataset_cmp(const void *, const void *)

    extern int zfs_create(libzfs_handle_t *, const char *, zfs.zfs_type_t,
        nvpair.nvlist_t *)
    extern int zfs_create_ancestors(libzfs_handle_t *, const char *)
    extern int zfs_destroy(zfs_handle_t *, int)
    extern int zfs_destroy_snaps(zfs_handle_t *, char *, int)
    extern int zfs_destroy_snaps_nvl(libzfs_handle_t *, nvpair.nvlist_t *, int)
    extern int zfs_clone(zfs_handle_t *, const char *, nvpair.nvlist_t *)
    extern int zfs_snapshot(libzfs_handle_t *, const char *, int, nvpair.nvlist_t *)
    extern int zfs_snapshot_nvl(libzfs_handle_t *hdl, nvpair.nvlist_t *snaps,
        nvpair.nvlist_t *props)
    extern int zfs_rollback(zfs_handle_t *, zfs_handle_t *, int)

    IF HAVE_RENAMEFLAGS_T:
        IF HAVE_RENAMEFLAGS_T_RECURSE:
            ctypedef struct renameflags_t:
                int recurse
                int nounmount
                int forceunmount
        ELSE:
            ctypedef struct renameflags_t:
                int recursive
                int nounmount
                int forceunmount

        IF HAVE_ZFS_RENAME == 4:
            extern int zfs_rename(zfs_handle_t *, const char *, const char *, renameflags_t flags)
        ELSE:
            extern int zfs_rename(zfs_handle_t *, const char *, renameflags_t)

    ELSE:

        extern int zfs_rename(zfs_handle_t *, const char *, boolean_t, boolean_t)

    IF HAVE_SENDFLAGS_T_COMPRESS:
        # FIXME: Please find a better way to do this
        IF HAVE_SENDFLAGS_T_VERBOSITY:
            ctypedef struct sendflags_t:
                int verbosity
                int replicate
                int doall
                int fromorigin
                int dedup
                int props
                int dryrun
                int parsable
                int progress
                int largeblock
                int embed_data
                int compress
                int raw
        ELSE:
            ctypedef struct sendflags_t:
                int verbose
                int replicate
                int doall
                int fromorigin
                int dedup
                int props
                int dryrun
                int parsable
                int progress
                int largeblock
                int embed_data
                int compress
                int raw
    ELSE:
        IF HAVE_SENDFLAGS_T_VERBOSITY:
            ctypedef struct sendflags_t:
                int verbosity
                int replicate
                int doall
                int fromorigin
                int dedup
                int props
                int dryrun
                int parsable
                int progress
                int largeblock
                int embed_data
                int compress
                int raw
        ELSE:
            ctypedef struct sendflags_t:
                int verbose
                int replicate
                int doall
                int fromorigin
                int dedup
                int props
                int dryrun
                int parsable
                int progress
                int largeblock
                int embed_data
                int raw

    ctypedef int (*snapfilter_cb_t)(zfs_handle_t *, void *)

    extern int zfs_send(zfs_handle_t *, const char *, const char *,
        sendflags_t *, int, snapfilter_cb_t, void *, nvpair.nvlist_t **) nogil

    IF HAVE_ZFS_SEND_ONE == 4:
        extern int zfs_send_one(zfs_handle_t *, const char *, int, int) nogil
    ELSE:
        extern int zfs_send_one(zfs_handle_t *, const char *, int) nogil

    IF HAVE_ZFS_SEND_RESUME or HAVE_ZFS_SEND_RESUME_TOKEN_TO_NVLIST:
        extern int zfs_send_resume(libzfs_handle_t *, sendflags_t *, int outfd, const char *)
        extern nvpair.nvlist_t *zfs_send_resume_token_to_nvlist(libzfs_handle_t *hdl, const char *token)

    extern int zfs_promote(zfs_handle_t *)
    extern int zfs_hold(zfs_handle_t *, const char *, const char *,
        int, int)
    extern int zfs_hold_nvl(zfs_handle_t *, int, nvpair.nvlist_t *)
    extern int zfs_release(zfs_handle_t *, const char *, const char *, int)
    extern int zfs_get_holds(zfs_handle_t *, nvpair.nvlist_t **)
    IF HAVE_ZVOLSIZE_TO_RESERVATION_PARAMS == 3:
        extern uint64_t zvol_volsize_to_reservation(zpool_handle_t *, uint64_t, nvpair.nvlist_t *);
    ELSE:
        extern uint64_t zvol_volsize_to_reservation(uint64_t, nvpair.nvlist_t *)

    extern int zfs_get_fsacl(zfs_handle_t *, nvpair.nvlist_t **)
    extern int zfs_set_fsacl(zfs_handle_t *, int, nvpair.nvlist_t *)

    ctypedef struct recvflags_t:
        int verbose
        int isprefix
        int istail
        int dryrun
        int force
        int canmountoff
        int resumable
        int byteswap
        int nomount

    ctypedef enum diff_flags_t:
        ZFS_DIFF_PARSEABLE = 0x1,
        ZFS_DIFF_TIMESTAMP = 0x2,
        ZFS_DIFF_CLASSIFY = 0x4

    IF HAVE_ZFS_RECEIVE == 7:
        extern int zfs_receive(libzfs_handle_t *, const char *, recvflags_t *,
            int, nvpair.nvlist_t *, nvpair.nvlist_t *, void *) # XXX: last argument should be avl_tree_t *
    ELIF HAVE_ZFS_RECEIVE == 6:
        extern int zfs_receive(libzfs_handle_t *, const char *, nvpair.nvlist_t *,
            recvflags_t *, int, void *) # XXX: last argument should be avl_tree_t *
    ELSE:
        extern int zfs_receive(libzfs_handle_t *, const char *, nvpair.nvlist_t *,
            recvflags_t *, int) # XXX: last argument should be avl_tree_t *

    extern int zfs_show_diffs(zfs_handle_t *, int, const char *, const char *,
        int)

    extern const char *zfs_type_to_name(zfs_type_t)
    extern void zfs_refresh_properties(zfs_handle_t *)
    extern int zfs_name_valid(const char *, zfs_type_t)
    extern zfs_handle_t *zfs_path_to_zhandle(libzfs_handle_t *, char *, zfs.zfs_type_t)
    extern int zfs_dataset_exists(libzfs_handle_t *, const char *,
        zfs_type_t)
    extern int zfs_spa_version(zfs_handle_t *, int *)
    extern int zfs_bookmark_exists(const char *path)

    extern int is_mounted(libzfs_handle_t *, const char *special, char **)
    extern int zfs_is_mounted(zfs_handle_t *, char **)
    extern int zfs_mount(zfs_handle_t *, const char *, int)
    extern int zfs_unmount(zfs_handle_t *, const char *, int)
    extern int zfs_unmountall(zfs_handle_t *, int)

    extern int zfs_is_shared(zfs_handle_t *)
    extern int zfs_share(zfs_handle_t *)
    extern int zfs_unshare(zfs_handle_t *)

    extern int zfs_is_shared_nfs(zfs_handle_t *, char **)
    extern int zfs_is_shared_smb(zfs_handle_t *, char **)
    extern int zfs_share_nfs(zfs_handle_t *)
    extern int zfs_share_smb(zfs_handle_t *)
    extern int zfs_shareall(zfs_handle_t *)
    extern int zfs_unshare_nfs(zfs_handle_t *, const char *)
    extern int zfs_unshare_smb(zfs_handle_t *, const char *)
    extern int zfs_unshareall_nfs(zfs_handle_t *)
    extern int zfs_unshareall_smb(zfs_handle_t *)
    extern int zfs_unshareall_bypath(zfs_handle_t *, const char *)
    extern int zfs_unshareall(zfs_handle_t *)
    extern int zfs_deleg_share_nfs(libzfs_handle_t *, char *, char *, char *,
        void *, void *, int, zfs_share_op_t)

    extern int zfs_jail(zfs_handle_t *, int, int)

    extern void zfs_nicenum(uint64_t, char *, size_t)
    extern int zfs_nicestrtonum(libzfs_handle_t *, const char *, uint64_t *)
    extern int zpool_in_use(libzfs_handle_t *, int, zfs.pool_state_t *, char **,
        int *)

    IF HAVE_ZPOOL_READ_LABEL_LIBZFS:
        IF HAVE_ZPOOL_READ_LABEL_PARAMS == 2:
            extern int zpool_read_label(int, nvpair.nvlist_t **)
        ELIF HAVE_ZPOOL_READ_LABEL_PARAMS == 3:
            extern int zpool_read_label(int, nvpair.nvlist_t **, int*)

    extern int zpool_clear_label(int)
    extern int zvol_check_dump_config(char *)

    int zfs_smb_acl_add(libzfs_handle_t *, char *, char *, char *)
    int zfs_smb_acl_remove(libzfs_handle_t *, char *, char *, char *)
    int zfs_smb_acl_purge(libzfs_handle_t *, char *, char *)
    int zfs_smb_acl_rename(libzfs_handle_t *, char *, char *, char *, char *)

    extern int zpool_enable_datasets(zpool_handle_t *, const char *, int)
    extern int zpool_disable_datasets(zpool_handle_t *, int)

    extern void libzfs_fru_refresh(libzfs_handle_t *)
    extern const char *libzfs_fru_lookup(libzfs_handle_t *, const char *)
    extern const char *libzfs_fru_devpath(libzfs_handle_t *, const char *)
    extern int libzfs_fru_compare(libzfs_handle_t *, const char *, const char *)
    extern int libzfs_fru_notself(libzfs_handle_t *, const char *)
    extern int zpool_fru_set(zpool_handle_t *, uint64_t, const char *)
    
    extern int zmount(const char *, const char *, int, char *, char *, int, char *,
        int)

    IF HAVE_ZFS_FOREACH_MOUNTPOINT:
        extern void zfs_foreach_mountpoint(
            libzfs_handle_t *, zfs_handle_t **, size_t, zfs_iter_f, void*, boolean_t
        )

    IF HAVE_ZFS_IOCTL_HEADER:
        extern int zfs_ioctl(libzfs_handle_t *, int request, zfs.zfs_cmd_t *)
    ELSE:
        ctypedef struct zfs_cmd:
            pass

        extern int zfs_ioctl(libzfs_handle_t *, int, zfs_cmd *)

    IF HAVE_ZFS_ENCRYPTION:
        extern int zfs_crypto_get_encryption_root(zfs_handle_t *, boolean_t *, char *)
        extern int zfs_crypto_create(
            libzfs_handle_t *, char *, nvpair.nvlist_t *, nvpair.nvlist_t *,
            boolean_t stdin_available, uint8_t **, uint_t *
        )
        extern int zfs_crypto_clone_check(libzfs_handle_t *, zfs_handle_t *, char *, nvpair.nvlist_t *)
        extern int zfs_crypto_attempt_load_keys(libzfs_handle_t *, char *)
        extern int zfs_crypto_load_key(zfs_handle_t *, boolean_t, char *)
        extern int zfs_crypto_unload_key(zfs_handle_t *)
        extern int zfs_crypto_rewrap(zfs_handle_t *, nvpair.nvlist_t *, boolean_t)

    IF HAVE_THREAD_INIT_FINI:
        cdef extern from 'sys/zfs_context_userland.h' nogil:
            extern void thread_init()
            extern void thread_fini()
