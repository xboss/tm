#ifndef _TCP_CONNECTION_H
#define _TCP_CONNECTION_H

#include <stdbool.h>
#include <uv.h>

#include "uthash.h"

typedef struct tcp_connection_s tcp_connection_t;
typedef struct tcp_server_s tcp_server_t;
// typedef struct tcp_client_s tcp_client_t;

typedef void (*on_tcp_connect_t)(tcp_connection_t *conn);
typedef void (*on_tcp_recv_t)(tcp_connection_t *conn, const char *buf, ssize_t size);
typedef void (*on_tcp_close_t)(tcp_connection_t *conn);

#define TCP_CONN_ST_OFF 0x00
#define TCP_CONN_ST_ON 0x01
#define TCP_CONN_ST_CLOSING 0x02

struct tcp_connection_s {
    int id;
    char status;
    uv_tcp_t *cli;
    tcp_server_t *serv;
    // tcp_client_t *cli;
    void *data;

    // on_tcp_accept_t on_accept;
    on_tcp_connect_t on_connect;
    on_tcp_recv_t on_recv;
    on_tcp_close_t on_close;

    UT_hash_handle hh;
};

tcp_connection_t *init_tcp_connection(int id, uv_tcp_t *cli, tcp_server_t *serv, void *data,
                                      on_tcp_connect_t on_connect, on_tcp_recv_t on_recv, on_tcp_close_t on_close);
// void free_tcp_connection(tcp_connection_t *conn);
bool tcp_send(tcp_connection_t *conn, const char *buf, ssize_t size);
void close_tcp_connection(tcp_connection_t *conn);
// void tcp_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
bool tcp_connect(uv_loop_t *loop, const char *ip, uint16_t port, void *data, on_tcp_connect_t on_connect,
                 on_tcp_recv_t on_recv, on_tcp_close_t on_close);

#endif  // TCP_CONNECTION_H