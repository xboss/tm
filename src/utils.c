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

void char_to_hex(const char *src, int len, char *des) {
    char hex_table[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    while (len--) {
        *(des++) = hex_table[(*src) >> 4];
        *(des++) = hex_table[*(src++) & 0x0f];
    }
}

void pwd2key(const char *pwd, char **key) {
    size_t pwd_len = strnlen(pwd, CIPHER_KEY_LEN / 2);
    *key = (char *)_CALLOC(1, CIPHER_KEY_LEN + 1);
    _CHECK_OOM(*key);
    memset(*key, 'F', CIPHER_KEY_LEN);
    char_to_hex(pwd, pwd_len, *key);
}

char *load_str_file(const char *filename) {
    FILE *fp;
    if ((fp = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "can't open file %s\n", filename);
        return NULL;
    }

    int r_buf_cnt = 2;
    char *str = (char *)_CALLOC(r_buf_cnt, FILE_R_BUF_SIZE);
    _CHECK_OOM(str);
    // TODO: _FREE_IF(str);

    char buf[FILE_R_BUF_SIZE] = {0};
    char *p = str;
    int js_len = 0;
    int p_offset = 0;
    while (fgets(buf, FILE_R_BUF_SIZE, fp) != NULL) {
        int len = strlen(buf);
        if (js_len + len > FILE_R_BUF_SIZE * r_buf_cnt) {
            // TODO:
            r_buf_cnt *= 2;
            _LOG("realloc read buffer %d", FILE_R_BUF_SIZE * r_buf_cnt);
            p_offset = p - str;
            str = realloc(str, FILE_R_BUF_SIZE * r_buf_cnt);
            _CHECK_OOM(str);
            p = str + p_offset;
        }
        memcpy(p, buf, len);
        p += len;
        js_len += len;
    }
    fclose(fp);
    return str;
}