# encoding: utf-8
# cython: language_level=3, c_string_type=unicode, c_string_encoding=default

cdef extern from "sys/types.h":
    ctypedef char int8_t
    ctypedef unsigned char uint8_t
    ctypedef unsigned char uchar_t
    ctypedef short int16_t
    ctypedef unsigned short uint16_t
    ctypedef int int32_t
    ctypedef int int_t
    ctypedef unsigned int uint_t
    ctypedef unsigned int uint32_t
    ctypedef long long int64_t
    ctypedef unsigned long long uint64_t
    ctypedef int boolean_t
    ctypedef long long hrtime_t
