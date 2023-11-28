#ifndef _TCP_SERVER_H
#define _TCP_SERVER_H

#include <uv.h>

#include "tcp_connection.h"

typedef struct tcp_server_s tcp_server_t;

typedef void (*on_tcp_accept_t)(tcp_connection_t *conn);

struct tcp_server_s {
    int cid;
    char *ip;
    uint16_t port;
    uv_tcp_t *tcp;
    uv_loop_t *loop;
    tcp_connection_t *conns;
    void *data;
    on_tcp_accept_t on_accept;
    on_tcp_recv_t on_recv;
    on_tcp_close_t on_close;
};

tcp_server_t *init_tcp_server(uv_loop_t *loop, const char *ip, uint16_t port, void *data, on_tcp_accept_t on_accept,
                              on_tcp_recv_t on_recv, on_tcp_close_t on_close);
void free_tcp_server(tcp_server_t *tcp_serv);

#endif  // TCP_SERVER_H