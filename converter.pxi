#+
# Copyright 2016 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################




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
            return int(value)

        if self.typ is str:
            return value

        if self.typ is bool:
            if value == self.yes:
                return True

            if value == self.no:
                return False

            return None

        if self.typ == datetime:
            return datetime.fromtimestamp(int(value))

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


ZPOOL_PROPERTY_CONVERTERS = {
    'name': ZfsConverter(str, readonly=True),
    'size': ZfsConverter(int, readonly=True, nullable=True),
    'capacity': ZfsConverter(str, readonly=True, nullable=True),
    'altroot': ZfsConverter(str, nullable=True),
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
    'mounted': ZfsConverter(bool, readonly=True),
    'quota': ZfsConverter(int, nullable=True, null='none', read_null='0'),
    'reservation': ZfsConverter(int, nullable=True, null='none', read_null='0'),
    'recordsize': ZfsConverter(str),
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
    'snapdir': ZfsConverter(bool, off='hidden', on='visible'),
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
    'filesystem_limit': ZfsConverter(int),
    'snapshot_limit': ZfsConverter(int),
    'filesystem_count': ZfsConverter(int, readonly=True),
    'snapshot_count': ZfsConverter(int, readonly=True),
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
