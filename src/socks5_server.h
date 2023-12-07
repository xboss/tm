#ifndef _SOCKS5_SERVER_H
#define _SOCKS5_SERVER_H

#include <stdbool.h>
#include <uv.h>

#include "n2n_server.h"

typedef struct socks5_server_s socks5_server_t;

typedef struct {
    int phase;
    socks5_server_t *socks5;
    u_char *raw;
    ssize_t raw_len;
    struct sockaddr_in target_addr;
} socks5_conn_t;

socks5_server_t *init_socks5_server(uv_loop_t *loop, const char *ip, uint16_t port);
void free_socks5_server(socks5_server_t *socks5);

#endif  // SOCKS5_SERVER_H