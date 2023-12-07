// #ifndef _SOCKS5_SERVER_H
// #define _SOCKS5_SERVER_H

// #include <stdbool.h>
// #include <uv.h>

// #include "tcp.h"

// typedef struct socks5_server_s socks5_server_t;
// // typedef struct socks5_connection_s socks5_connection_t;

// typedef struct {
//     int phase;
//     // int fr_id;
//     // int bk_id;
//     tcp_connection_t *fr_conn;
//     tcp_connection_t *bk_conn;
//     socks5_server_t *socks5;
//     u_char *raw;
//     ssize_t raw_len;
//     uint16_t port;
//     char ip[47];
//     // int ref_cnt;

//     // uv_getaddrinfo_t *resolver;
//     // u_char atyp;
//     // u_char *addr_raw;
//     // size_t addr_raw_len;
//     // u_char port_raw[2];
//     void *data;
// } socks5_connection_t;

// // typedef void (*on_socks5_accept_t)(socks5_connection_t *conn);
// // typedef int (*on_socks5_recv_t)(socks5_connection_t *conn, const char *buf, ssize_t size);
// // typedef void (*on_socks5_close_t)(socks5_connection_t *conn);

// socks5_server_t *init_socks5_server(uv_loop_t *loop, const char *ip, uint16_t port);
// void free_socks5_server(socks5_server_t *socks5);
// // bool socks5_server_send(socks5_connection_t *conn, const char *buf, ssize_t size);
// // bool socks5_server_bind_conn_data(socks5_server_t *socks5, int conn_id, void *data);
// // void *socks5_server_get_conn_data(socks5_server_t *socks5, int conn_id);
// // socks5_connection_t *socks5_server_get_conn(socks5_server_t *socks5, int conn_id);

// #endif  // SOCKS5_SERVER_H