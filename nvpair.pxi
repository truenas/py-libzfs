# encoding: utf-8
# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

cimport nvpair
import collections
import numbers
import cython
from types cimport *
from libc.stdint cimport uintptr_t
from libc.stdlib cimport malloc, free

from collections.abc import Sequence


@cython.internal
cdef class NVList(object):
    cdef nvpair.nvlist_t* handle
    cdef int foreign

    def __init__(self, uintptr_t nvlist=0, otherdict=None):
        if nvlist:
            self.foreign = True
            self.handle = <nvpair.nvlist_t*>nvlist
        else:
            self.foreign = False
            nvpair.nvlist_alloc(&self.handle, nvpair.NV_UNIQUE_NAME, 0)

        if otherdict:
            for k, v in otherdict.items():
                self[k] = v


    def __dealloc__(self):
        if not self.foreign:
            nvpair.nvlist_free(self.handle)
            self.handle = NULL

    cdef object get_raw(self, key):
        cdef nvpair.nvpair_t* pair = self.__get_pair(key)
        return self.__get_value(pair, False)

    cdef nvpair.nvpair_t* __get_pair(self, key) except NULL:
        cdef nvpair.nvpair_t* pair
        if nvpair.nvlist_lookup_nvpair(self.handle, key, &pair) != 0:
            raise ValueError('Key {0} not found'.format(key))

        return pair

    cdef object __get_value(self, nvpair.nvpair_t* pair, wrap_dict=True):
        cdef nvpair.nvlist_t *nested
        cdef const char *cstr
        cdef void *carray
        cdef uint_t carraylen
        cdef bint boolean
        cdef int32_t cint
        cdef uint64_t clong
        cdef int datatype

        datatype = nvpair.nvpair_type(pair)

        if datatype == nvpair.DATA_TYPE_STRING:
            nvpair.nvpair_value_string(pair, &cstr)
            return (<bytes>cstr).decode('utf-8')

        if datatype == nvpair.DATA_TYPE_BOOLEAN:
            nvpair.nvpair_value_boolean_value(pair, <boolean_t*>&boolean)
            return boolean

        if datatype == nvpair.DATA_TYPE_BYTE:
            nvpair.nvpair_value_byte(pair, <uchar_t*>&cint)
            return cint

        if datatype == nvpair.DATA_TYPE_INT8:
            nvpair.nvpair_value_int8(pair, <int8_t*>&cint)
            return cint

        if datatype == nvpair.DATA_TYPE_UINT8:
            nvpair.nvpair_value_uint8(pair, <uint8_t*>&cint)
            return cint

        if datatype == nvpair.DATA_TYPE_INT16:
            nvpair.nvpair_value_int16(pair, <int16_t*>&cint)
            return cint

        if datatype == nvpair.DATA_TYPE_UINT16:
            nvpair.nvpair_value_uint16(pair, <uint16_t*>&cint)
            return cint

        if datatype == nvpair.DATA_TYPE_INT32:
            nvpair.nvpair_value_int32(pair, <int32_t*>&cint)
            return cint

        if datatype == nvpair.DATA_TYPE_UINT32:
            nvpair.nvpair_value_uint32(pair, <uint32_t*>&clong)
            return clong

        if datatype == nvpair.DATA_TYPE_INT64:
            nvpair.nvpair_value_int64(pair, <int64_t*>&clong)
            return clong

        if datatype == nvpair.DATA_TYPE_UINT64:
            nvpair.nvpair_value_uint64(pair, <uint64_t*>&clong)
            return clong

        if datatype == nvpair.DATA_TYPE_BYTE_ARRAY:
            nvpair.nvpair_value_byte_array(pair, <uchar_t**>&carray, &carraylen)
            return [x for x in (<uchar_t *>carray)[:carraylen]]

        if datatype == nvpair.DATA_TYPE_INT8_ARRAY:
            nvpair.nvpair_value_int8_array(pair, <int8_t**>&carray, &carraylen)
            return [x for x in (<uint8_t *>carray)[:carraylen]]

        if datatype == nvpair.DATA_TYPE_UINT8_ARRAY:
            nvpair.nvpair_value_uint8_array(pair, <uint8_t**>&carray, &carraylen)
            return [x for x in (<uint8_t *>carray)[:carraylen]]

        if datatype == nvpair.DATA_TYPE_INT16_ARRAY:
            nvpair.nvpair_value_int16_array(pair, <int16_t**>&carray, &carraylen)
            return [x for x in (<int16_t *>carray)[:carraylen]]

        if datatype == nvpair.DATA_TYPE_UINT16_ARRAY:
            nvpair.nvpair_value_uint16_array(pair, <uint16_t**>&carray, &carraylen)
            return [x for x in (<uint16_t *>carray)[:carraylen]]

        if datatype == nvpair.DATA_TYPE_INT32_ARRAY:
            nvpair.nvpair_value_int32_array(pair, <int32_t**>&carray, &carraylen)
            return [x for x in (<int32_t *>carray)[:carraylen]]

        if datatype == nvpair.DATA_TYPE_UINT32_ARRAY:
            nvpair.nvpair_value_uint32_array(pair, <uint32_t**>&carray, &carraylen)
            return [x for x in (<uint32_t *>carray)[:carraylen]]

        if datatype == nvpair.DATA_TYPE_INT64_ARRAY:
            nvpair.nvpair_value_int64_array(pair, <int64_t**>&carray, &carraylen)
            return [x for x in (<int64_t *>carray)[:carraylen]]

        if datatype == nvpair.DATA_TYPE_UINT64_ARRAY:
            nvpair.nvpair_value_uint64_array(pair, <uint64_t**>&carray, &carraylen)
            return [x for x in (<uint64_t *>carray)[:carraylen]]

        if datatype == nvpair.DATA_TYPE_STRING_ARRAY:
            nvpair.nvpair_value_string_array(pair, <const char***>&carray, &carraylen)
            return [x for x in (<const char**>carray)[:carraylen]]

        if datatype == nvpair.DATA_TYPE_NVLIST:
            nvpair.nvpair_value_nvlist(pair, &nested)
            return dict(NVList(<uintptr_t>nested)) if wrap_dict else NVList(<uintptr_t>nested)

        if datatype == nvpair.DATA_TYPE_NVLIST_ARRAY:
            nvpair.nvpair_value_nvlist_array(pair, <nvpair.nvlist_t***>&carray, &carraylen)
            return [dict(NVList(x)) if wrap_dict else NVList(x) for x in (<uintptr_t *>carray)[:carraylen]]

    cdef int nvlist_lookup_uint64_array(self, nvpair.nvlist_t* nvl, const char* buf, uint64_t **a, uint_t *n):
        return nvpair.nvlist_lookup_uint64_array(nvl, buf, a, n)

    def __contains__(self, key):
        return nvpair.nvlist_exists(self.handle, key)

    def __delitem__(self, key):
        nvpair.nvlist_remove(self.handle, key, self.type(key))

    def __iter__(self):
        cdef nvpair.nvpair_t *pair = NULL
        while True:
            pair = nvpair.nvlist_next_nvpair(self.handle, pair)
            if pair is NULL:
                return

            yield nvpair.nvpair_name(pair)

    def get(self, key, object default=None):
        if not key in self:
            return default

        return self[key]

    def type(self, key):
        cdef nvpair.nvpair_t *pair = self.__get_pair(key)
        return nvpair.nvpair_type(pair)

    def set(self, key, value, typeid):
        cdef NVList cnvlist
        cdef void* carray = NULL
        cdef uintptr_t cptr

        # Oh god, this is tedious...

        if isinstance(value, (str, unicode)):
            if typeid == nvpair.DATA_TYPE_STRING:
                nvpair.nvlist_add_string(self.handle, key, value)
                return

        if isinstance(value, type(None)):
            if typeid == nvpair.DATA_TYPE_BOOLEAN:
                nvpair.nvlist_add_boolean(self.handle, key)
                return

        if isinstance(value, bool):
            if typeid == nvpair.DATA_TYPE_BOOLEAN:
                nvpair.nvlist_add_boolean_value(self.handle, key, <boolean_t>value)
                return

        if isinstance(value, numbers.Number):
            if typeid == nvpair.DATA_TYPE_BYTE:
                nvpair.nvlist_add_byte(self.handle, key, <char>value)
                return

            if typeid == nvpair.DATA_TYPE_UINT8:
                nvpair.nvlist_add_uint8(self.handle, key, <uint8_t>value)
                return

            if typeid == nvpair.DATA_TYPE_INT8:
                nvpair.nvlist_add_int8(self.handle, key, <int8_t>value)
                return

            if typeid == nvpair.DATA_TYPE_UINT16:
                nvpair.nvlist_add_uint16(self.handle, key, <uint16_t>value)
                return

            if typeid == nvpair.DATA_TYPE_INT16:
                nvpair.nvlist_add_int16(self.handle, key, <int16_t>value)
                return

            if typeid == nvpair.DATA_TYPE_UINT32:
                nvpair.nvlist_add_uint32(self.handle, key, <uint32_t>value)
                return

            if typeid == nvpair.DATA_TYPE_INT32:
                nvpair.nvlist_add_int32(self.handle, key, <int32_t>value)
                return

            if typeid == nvpair.DATA_TYPE_UINT64:
                nvpair.nvlist_add_uint64(self.handle, key, <uint64_t>value)
                return

            if typeid == nvpair.DATA_TYPE_INT64:
                nvpair.nvlist_add_int64(self.handle, key, <int64_t>value)
                return

        if isinstance(value, NVList):
            if typeid == nvpair.DATA_TYPE_NVLIST:
                cnvlist = <NVList>value
                nvpair.nvlist_add_nvlist(self.handle, key, cnvlist.handle)
                return

        if isinstance(value, dict):
            if typeid == nvpair.DATA_TYPE_NVLIST:
                cnvlist = NVList(otherdict=value)
                nvpair.nvlist_add_nvlist(self.handle, key, cnvlist.handle)
                return

        if isinstance(value, Sequence):
            if typeid == nvpair.DATA_TYPE_STRING_ARRAY:
                carray = malloc(len(value) * sizeof(char*))
                for idx, i in enumerate(value):
                    (<char**>carray)[idx] = i

                nvpair.nvlist_add_string_array(self.handle, key, <const char* const*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_BOOLEAN_ARRAY:
                carray = malloc(len(value) * sizeof(char*))
                for idx, i in enumerate(value):
                    (<boolean_t*>carray)[idx] = i

                nvpair.nvlist_add_boolean_array(self.handle, key, <boolean_t*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_BYTE_ARRAY:
                carray = malloc(len(value) * sizeof(char))
                for idx, i in enumerate(value):
                    (<char*>carray)[idx] = i

                nvpair.nvlist_add_byte_array(self.handle, key, <uchar_t*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_UINT8_ARRAY:
                carray = malloc(len(value) * sizeof(uint8_t))
                for idx, i in enumerate(value):
                    (<uint8_t*>carray)[idx] = i

                nvpair.nvlist_add_uint8_array(self.handle, key, <uint8_t*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_INT8_ARRAY:
                carray = malloc(len(value) * sizeof(int8_t))
                for idx, i in enumerate(value):
                    (<int8_t*>carray)[idx] = i

                nvpair.nvlist_add_int8_array(self.handle, key, <int8_t*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_UINT16_ARRAY:
                carray = malloc(len(value) * sizeof(uint16_t))
                for idx, i in enumerate(value):
                    (<uint16_t*>carray)[idx] = i

                nvpair.nvlist_add_uint16_array(self.handle, key, <uint16_t*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_INT16_ARRAY:
                carray = malloc(len(value) * sizeof(int16_t))
                for idx, i in enumerate(value):
                    (<uint16_t*>carray)[idx] = i


                nvpair.nvlist_add_int16_array(self.handle, key, <int16_t*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_UINT32_ARRAY:
                carray = malloc(len(value) * sizeof(uint32_t))
                for idx, i in enumerate(value):
                    (<uint32_t*>carray)[idx] = i

                nvpair.nvlist_add_uint32_array(self.handle, key, <uint32_t*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_INT32_ARRAY:
                carray = malloc(len(value) * sizeof(int32_t))
                for idx, i in enumerate(value):
                    (<int32_t*>carray)[idx] = i

                nvpair.nvlist_add_int32_array(self.handle, key, <int32_t*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_UINT64_ARRAY:
                carray = malloc(len(value) * sizeof(uint64_t))
                for idx, i in enumerate(value):
                    (<uint64_t*>carray)[idx] = i

                nvpair.nvlist_add_uint64_array(self.handle, key, <uint64_t*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_INT64_ARRAY:
                carray = malloc(len(value) * sizeof(int64_t))
                for idx, i in enumerate(value):
                    (<int64_t*>carray)[idx] = i

                nvpair.nvlist_add_int64_array(self.handle, key, <int64_t*>carray, len(value))

            if typeid == nvpair.DATA_TYPE_NVLIST_ARRAY:
                carray = malloc(len(value) * sizeof(nvpair.nvlist_t*))
                for idx, i in enumerate(value):
                    cnvlist = <NVList>i
                    (<uintptr_t*>carray)[idx] = <uintptr_t>cnvlist.handle

                nvpair.nvlist_add_nvlist_array(self.handle, key, <const nvpair.nvlist_t* const*>carray, len(value))

            if carray != NULL:
                free(carray)

            return

        raise ValueError('Value not compatible with type specified: {0}'.format(type(value).__name__))

    def __getitem__(self, key):
        cdef nvpair.nvpair_t *pair

        pair = self.__get_pair(key)
        return self.__get_value(pair)

    def __setitem__(self, key, value):
        if type(key) is unicode:
            key = str(key)

        if type(value) is bool or value is None:
            self.set(key, value, nvpair.DATA_TYPE_BOOLEAN)

        if type(value) is int:
            self.set(key, value, nvpair.DATA_TYPE_UINT64)

        if type(value) is str or type(value) is unicode:
            self.set(key, str(value), nvpair.DATA_TYPE_STRING)

        if type(value) is NVList:
            self.set(key, value, nvpair.DATA_TYPE_NVLIST)

        if type(value) is list:
            # We need some heuristics here...
            if len(value) == 0:
                # don't know what to do!
                return

            if type(value[0]) is NVList:
                self.set(key, value, nvpair.DATA_TYPE_NVLIST_ARRAY)

            if type(value[0]) is int:
                self.set(key, value, nvpair.DATA_TYPE_INT32_ARRAY)

            if type(value[0]) is long:
                self.set(key, value, nvpair.DATA_TYPE_INT64_ARRAY)

            if type(value[0]) is str or type(value) is unicode:
                self.set(key, value, nvpair.DATA_TYPE_STRING_ARRAY)

        if type(value) is dict:
            self.set(key, value, nvpair.DATA_TYPE_NVLIST)

    def get_type(self, key):
        pair = self.__get_pair(key)
        return nvpair.nvpair_type(pair)

    def keys(self):
        return list(self)

    def values(self):
        return [v for k, v in self.items()]

    def items(self, raw=False):
        cdef nvpair.nvpair_t *pair = NULL
        while True:
            pair = nvpair.nvlist_next_nvpair(self.handle, pair)
            if pair is NULL:
                return

            yield (nvpair.nvpair_name(pair), self.__get_value(pair, not raw))
