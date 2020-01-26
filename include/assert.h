#include_next <assert.h>

#ifndef __assert
#define __assert(e, file, line) \
    ((void)printf ("%s:%d: failed assertion `%s'\n", file, line, e), abort())
#endif
