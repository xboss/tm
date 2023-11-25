#ifndef _SOCKS5_SERVER_H
#define _SOCKS5_SERVER_H

#include <stdbool.h>
#include <uv.h>

#include "uthash.h"

typedef struct socks5_server_s socks5_server_t;
typedef struct socks5_connection_s socks5_connection_t;

typedef void (*on_socks5_accept_t)(socks5_server_t *socks5, int conn_id);
typedef int (*on_socks5_recv_t)(socks5_server_t *socks5, int conn_id, const char *buf, ssize_t size);
typedef void (*on_socks5_close_t)(socks5_server_t *socks5, int conn_id);

struct socks5_server_s {
    char *ip;
    uint16_t port;
    uv_tcp_t *tcp;
    uv_loop_t *loop;
    socks5_connection_t *conns;
    on_socks5_accept_t on_accept;
    on_socks5_recv_t on_recv;
    on_socks5_close_t on_close;
};

struct socks5_connection_s {
    int id;
    uv_tcp_t *client;
    socks5_server_t *socks5;
    void *data;
    UT_hash_handle hh;
};

socks5_server_t *init_socks5_server(uv_loop_t *loop, const char *ip, uint16_t port, on_socks5_accept_t on_accept,
                                    on_socks5_recv_t on_recv, on_socks5_close_t on_close);
void free_socks5_server(socks5_server_t *socks5);
bool socks5_server_send(socks5_server_t *socks5, int conn_id, const char *buf, ssize_t size);
socks5_connection_t *socks5_server_get_conn(socks5_server_t *socks5, int conn_id);

#endif  // SOCKS5_SERVER_H