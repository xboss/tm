#ifndef _TCP_H
#define _TCP_H

#include <stdbool.h>
#include <uv.h>

#include "uthash.h"

#define TCP_MAX_IP_LEN 46

typedef struct tcp_s tcp_t;

typedef void (*on_tcp_accept_t)(tcp_t *tcp, int conn_id);
typedef void (*on_tcp_connect_t)(tcp_t *tcp, int conn_id);
typedef void (*on_tcp_recv_t)(tcp_t *tcp, int conn_id, const char *buf, ssize_t size);
typedef void (*on_tcp_close_t)(tcp_t *tcp, int conn_id);

typedef enum { tcp_conn_mode_none = 0, tcp_conn_mode_server, tcp_conn_mode_client } tcp_conn_mode_t;

typedef struct {
    int backlog;
    size_t read_buf_size;
} tcp_option_t;

tcp_t *init_tcp(uv_loop_t *loop, void *data, on_tcp_accept_t on_accept, on_tcp_connect_t on_connect,
                on_tcp_recv_t on_recv, on_tcp_close_t on_close, const tcp_option_t *opts);
void free_tcp(tcp_t *tcp);
void set_tcp_data(tcp_t *tcp, void *data);
void *get_tcp_data(tcp_t *tcp);

bool start_tcp_server_with_sockaddr(tcp_t *tcp, struct sockaddr_in sockaddr);
bool start_tcp_server(tcp_t *tcp, const char *ip, uint16_t port);
void stop_tcp_server(tcp_t *tcp);

int connect_tcp_with_sockaddr(tcp_t *tcp, struct sockaddr_in sockaddr, void *data);
int connect_tcp(tcp_t *tcp, const char *ip, uint16_t port, void *data);
void close_tcp_connection(tcp_t *tcp, int conn_id);

bool tcp_send(tcp_t *tcp, int conn_id, const char *buf, ssize_t size);
bool is_tcp_connection(tcp_t *tcp, int conn_id);
void *get_tcp_conn_data(tcp_t *tcp, int conn_id);
void set_tcp_conn_data(tcp_t *tcp, int conn_id, void *data);
tcp_conn_mode_t get_tcp_conn_mode(tcp_t *tcp, int conn_id);
uint64_t get_tcp_conn_last_r_tm(tcp_t *tcp, int conn_id);
uint64_t get_tcp_conn_last_w_tm(tcp_t *tcp, int conn_id);

#endif /* TCP_H */