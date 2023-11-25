#ifndef _UTILS_H
#define _UTILS_H

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _FREE_IF
#define _FREE_IF(p)     \
    do {                \
        if ((p)) {      \
            free((p));  \
            (p) = NULL; \
        }               \
    } while (0)
#endif

#ifndef _CALLOC
#define _CALLOC(_cnt, _size) calloc(_cnt, (_size))
#endif

#ifndef _CHECK_OOM
#define _CHECK_OOM(p)                             \
    if (!p) {                                     \
        fprintf(stderr, "%s\n", strerror(errno)); \
        exit(1);                                  \
    }
#endif

#ifndef _LOG
#define _LOG(fmt, args...)   \
    do {                     \
        printf(fmt, ##args); \
        printf("\n");        \
    } while (0)
#endif

#define IF_UV_ERROR(_r, _msg, _act)                           \
    if ((_r) < 0) {                                           \
        fprintf(stderr, "" #_msg " %s\n", uv_strerror((_r))); \
        _act                                                  \
    }

uint64_t ustime();
uint64_t mstime();
char *load_str_file(const char *filename);

#endif  // UTILS_H