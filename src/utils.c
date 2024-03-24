#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <uv.h>

#ifndef FILE_R_BUF_SIZE
#define FILE_R_BUF_SIZE 1024
#endif

uint64_t ustime() {
    uv_timespec64_t ts;
    uv_clock_gettime(UV_CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000L + ((uint64_t)ts.tv_nsec) / 1000L;
}

uint64_t mstime() { return ustime() / 1000L; }

char *load_str_file(const char *filename) {
    FILE *fp;
    if ((fp = fopen(filename, "r")) == NULL) {
        _ERR("can't open file %s", filename);
        return NULL;
    }

    int r_buf_cnt = 2;
    char *str = (char *)_CALLOC(r_buf_cnt, FILE_R_BUF_SIZE);
    _CHECK_OOM(str);

    char buf[FILE_R_BUF_SIZE] = {0};
    char *p = str;
    int rd_len = 0;
    int p_offset = 0;
    while (fgets(buf, FILE_R_BUF_SIZE, fp) != NULL) {
        int len = strlen(buf);
        if (rd_len + len > FILE_R_BUF_SIZE * r_buf_cnt) {
            /* TODO: */
            r_buf_cnt *= 2;
            _LOG("realloc read buffer %d", FILE_R_BUF_SIZE * r_buf_cnt);
            p_offset = p - str;
            str = realloc(str, FILE_R_BUF_SIZE * r_buf_cnt);
            _CHECK_OOM(str);
            p = str + p_offset;
        }
        memcpy(p, buf, len);
        p += len;
        rd_len += len;
    }
    fclose(fp);
    return str;
}