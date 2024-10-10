class ZfsConverter(object):
    def __init__(self, typ, **kwargs):
        self.typ = typ
        self.readonly = kwargs.pop('readonly', False)
        self.nullable = kwargs.pop('nullable', False)
        self.null = kwargs.pop('null', '-')
        self.read_null = kwargs.pop('read_null', self.null)
        self.no = kwargs.pop('no', 'off')
        self.yes = kwargs.pop('yes', 'on')

    def to_native(self, value):
        if value is None:
            return None

        if self.nullable and value == self.read_null:
            return None

        if self.typ is int:
            try:
                return int(value)
            except ValueError:
                return None

        if self.typ is str:
            return value

        if self.typ is bool:
            if value == self.yes:
                return True

            if value == self.no:
                return False

            return None

        if self.typ == datetime:
            return datetime.utcfromtimestamp(int(value))

    def to_property(self, value):
        if self.readonly:
            raise ValueError('Property is read-only')

        if value is None:
            if not self.nullable:
                raise ValueError('Property is not nullable')

            return self.null

        if self.typ is int:
            return str(value)

        if self.typ is str:
            return value

        if self.typ is bool:
            return self.yes if value else self.no

        if self.typ is datetime:
            return str(value.timestamp())

UINT64_MAX = '18446744073709551615'


ZPOOL_PROPERTY_CONVERTERS = {
    'name': ZfsConverter(str, readonly=True),
    'size': ZfsConverter(int, readonly=True, nullable=True),
    'capacity': ZfsConverter(str, readonly=True, nullable=True),
    'altroot': ZfsConverter(str, nullable=True),
    'ashift': ZfsConverter(int),
    'health': ZfsConverter(str, readonly=True),
    'guid': ZfsConverter(int, readonly=True),
    'version': ZfsConverter(int, nullable=True),
    'bootfs': ZfsConverter(str, nullable=True),
    'delegation': ZfsConverter(bool, nullable=True),
    'autoreplace': ZfsConverter(bool, nullable=True),
    'cachemode': ZfsConverter(str, nullable=True),
    'failmode': ZfsConverter(str, nullable=True),
    'listsnapshots': ZfsConverter(bool, nullable=True),
    'autoexpand': ZfsConverter(bool, nullable=True),
    'dedupditto': ZfsConverter(int, readonly=True, nullable=True),
    'dedupratio': ZfsConverter(str, readonly=True, nullable=True),
    'free': ZfsConverter(int, readonly=True, nullable=True),
    'allocated': ZfsConverter(int, readonly=True, nullable=True),
    'readonly': ZfsConverter(bool, nullable=True),
    'comment': ZfsConverter(str, nullable=True),
    'expandsize': ZfsConverter(int, nullable=True),
    'freeing': ZfsConverter(int, readonly=True, nullable=True),
    'fragmentation': ZfsConverter(str, readonly=True, nullable=True),
    'leaked': ZfsConverter(int, readonly=True, nullable=True)
}


ZFS_PROPERTY_CONVERTERS = {
    'type': ZfsConverter(str, readonly=True),
    'creation': ZfsConverter(datetime, readonly=True),
    'used': ZfsConverter(int, readonly=True),
    'available': ZfsConverter(int, readonly=True),
    'referenced': ZfsConverter(int, readonly=True),
    'mounted': ZfsConverter(bool, readonly=True, yes='yes', no='no'),
    'quota': ZfsConverter(int, nullable=True, null='none', read_null='0'),
    'reservation': ZfsConverter(int, nullable=True, null='none', read_null='0'),
    'recordsize': ZfsConverter(int, nullable=True),
    'mountpoint': ZfsConverter(str),
    'sharenfs': ZfsConverter(str, nullable=True, null='off'),
    'checksum': ZfsConverter(bool),
    'compression': ZfsConverter(str),
    'atime': ZfsConverter(bool),
    'devices': ZfsConverter(bool),
    'exec': ZfsConverter(bool),
    'setuid': ZfsConverter(bool),
    'readonly': ZfsConverter(bool),
    'jailed': ZfsConverter(bool),
    'snapdir': ZfsConverter(str),
    'aclmode': ZfsConverter(str),
    'aclinherit': ZfsConverter(str),
    'canmount': ZfsConverter(bool),
    'xattr': ZfsConverter(bool),
    'copies': ZfsConverter(int),
    'version': ZfsConverter(int, nullable=True, null=''),
    'utf8only': ZfsConverter(bool),
    'normalization': ZfsConverter(str),
    'casesensitivity': ZfsConverter(str),
    'vscan': ZfsConverter(bool),
    'nbmand': ZfsConverter(bool),
    'sharesmb': ZfsConverter(str, nullable=True, null='off'),
    'refquota': ZfsConverter(int, nullable=True, null='none', read_null='0'),
    'refreservation': ZfsConverter(int, nullable=True, null='none', read_null='0'),
    'primarycache': ZfsConverter(str),
    'secondarycache': ZfsConverter(str),
    'usedbysnapshots': ZfsConverter(int, readonly=True),
    'usedbydataset': ZfsConverter(int, readonly=True),
    'usedbychildren': ZfsConverter(int, readonly=True),
    'usedbyrefreservation': ZfsConverter(int, readonly=True),
    'logbias': ZfsConverter(str),
    'dedup': ZfsConverter(str),
    'mislabel': ZfsConverter(str),
    'sync': ZfsConverter(str),
    'refcompressratio': ZfsConverter(str, readonly=True),
    'written': ZfsConverter(int, readonly=True),
    'logicalused': ZfsConverter(int, readonly=True),
    'logicalreferenced': ZfsConverter(int, readonly=True),
    'volmode': ZfsConverter(str),
    'volsize': ZfsConverter(int),
    'volblocksize': ZfsConverter(int),
    'filesystem_limit': ZfsConverter(int, nullable=True, read_null=UINT64_MAX),
    'snapshot_limit': ZfsConverter(int, nullable=True, read_null=UINT64_MAX),
    'filesystem_count': ZfsConverter(int, readonly=True, nullable=True, read_null=UINT64_MAX),
    'snapshot_count': ZfsConverter(int, readonly=True, nullable=True, read_null=UINT64_MAX),
    'redundant_metadata': ZfsConverter(str)
}


def parse_zfs_prop(prop, value):
    try:
        return ZFS_PROPERTY_CONVERTERS[prop].to_native(value)
    except KeyError:
        return value


def serialize_zfs_prop(prop, value):
    try:
        return ZFS_PROPERTY_CONVERTERS[prop].to_property(value)
    except KeyError:
        return value


def parse_zpool_prop(prop, value):
    try:
        return ZPOOL_PROPERTY_CONVERTERS[prop].to_native(value)
    except KeyError:
        return value


def serialize_zpool_prop(prop, value):
    try:
        return ZPOOL_PROPERTY_CONVERTERS[prop].to_property(value)
    except KeyError:
        return value
