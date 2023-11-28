#ifndef _SOCKS5_SERVER_H
#define _SOCKS5_SERVER_H

#include <stdbool.h>
#include <uv.h>

typedef struct socks5_server_s socks5_server_t;
// typedef struct socks5_connection_s socks5_connection_t;

typedef void (*on_socks5_accept_t)(socks5_server_t *socks5, int conn_id);
typedef int (*on_socks5_recv_t)(socks5_server_t *socks5, int conn_id, const char *buf, ssize_t size);
typedef void (*on_socks5_close_t)(socks5_server_t *socks5, int conn_id);

socks5_server_t *init_socks5_server(uv_loop_t *loop, const char *ip, uint16_t port, on_socks5_accept_t on_accept,
                                    on_socks5_recv_t on_recv, on_socks5_close_t on_close);
void free_socks5_server(socks5_server_t *socks5);
bool socks5_server_send(socks5_server_t *socks5, int conn_id, const char *buf, ssize_t size);
bool socks5_server_bind_conn_data(socks5_server_t *socks5, int conn_id, void *data);
void *socks5_server_get_conn_data(socks5_server_t *socks5, int conn_id);
// socks5_connection_t *socks5_server_get_conn(socks5_server_t *socks5, int conn_id);

#endif  // SOCKS5_SERVER_H