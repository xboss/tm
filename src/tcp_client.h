#ifndef _TCP_CLIENT_H
#define _TCP_CLIENT_H

#include "tcp_connection.h"

// typedef struct {
//     tcp_connection_t *conn;
// } tcp_client_t;

tcp_connection_t *tcp_connect(uv_loop_t *loop, const char *ip, uint16_t port, void *data, on_tcp_accept_t on_accept,
                              on_tcp_connect_t on_connect, on_tcp_recv_t on_recv, on_tcp_close_t on_close);

#endif  // TCP_CLIENT_H