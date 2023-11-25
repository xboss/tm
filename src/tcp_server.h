#ifndef _TCP_SERVER_H
#define _TCP_SERVER_H

#include <stdbool.h>
#include <uv.h>

#include "uthash.h"

typedef struct tcp_server_s tcp_server_t;
typedef struct tcp_connection_s tcp_connection_t;

typedef void (*on_tcp_accept_t)(tcp_server_t *tcp_serv, int conn_id);
typedef void (*on_tcp_recv_t)(tcp_server_t *tcp_serv, int conn_id, const char *buf, ssize_t size);
typedef void (*on_tcp_close_t)(tcp_server_t *tcp_serv, int conn_id);

struct tcp_server_s {
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

struct tcp_connection_s {
    int id;
    uv_tcp_t *client;
    tcp_server_t *tcp_serv;
    void *data;
    UT_hash_handle hh;
};

tcp_server_t *init_tcp_server(uv_loop_t *loop, const char *ip, uint16_t port, on_tcp_accept_t on_accept,
                              on_tcp_recv_t on_recv, on_tcp_close_t on_close);
void free_tcp_server(tcp_server_t *tcp_serv);
bool tcp_server_send(tcp_server_t *tcp_serv, int conn_id, const char *buf, ssize_t size);
tcp_connection_t *get_tcp_server_conn(tcp_server_t *tcp_serv, int conn_id);
void close_tcp_server_conn(tcp_server_t *tcp_serv, int conn_id);

#endif  // TCP_SERVER_H