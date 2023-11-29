#ifndef _TCP_H
#define _TCP_H

#include <stdbool.h>
#include <uv.h>

#include "uthash.h"

typedef struct tcp_connection_s tcp_connection_t;
typedef struct tcp_s tcp_t;

typedef void (*on_tcp_accept_t)(tcp_t *tcp, int conn_id);
typedef void (*on_tcp_connect_t)(tcp_t *tcp, int conn_id);
typedef void (*on_tcp_recv_t)(tcp_t *tcp, int conn_id, const char *buf, ssize_t size);
typedef void (*on_tcp_close_t)(tcp_t *tcp, int conn_id);

struct tcp_connection_s {
    int id;
    char *c_ip;
    uint16_t c_port;
    uv_tcp_t *cli;
    char status;
    tcp_t *tcp;
    void *data;

    UT_hash_handle hh;
};

struct tcp_s {
    char *s_ip;
    uint16_t s_port;
    uv_tcp_t *serv;
    uv_loop_t *loop;
    tcp_connection_t *conns;
    void *data;

    on_tcp_accept_t on_accept;
    on_tcp_connect_t on_connect;
    on_tcp_recv_t on_recv;
    on_tcp_close_t on_close;
};

tcp_t *init_tcp();
bool start_tcp_server(tcp_t *tcp, );
void stop_tcp_server(tcp_t *tcp);
int connect_tcp(tcp_t *tcp, );
void close_tcp_connection(tcp_t *tcp, int conn_id);
bool tcp_send(tcp_t *tcp, int conn_id, const char *buf, ssize_t size);
tcp_connection_t *get_tcp_connection(tcp_t *tcp, int conn_id);

#endif  // TCP_H