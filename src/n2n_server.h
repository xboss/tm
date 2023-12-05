#ifndef _N2N_SERVER_H
#define _N2N_SERVER_H

#include <stdbool.h>
#include <uv.h>

#include "tcp.h"
#include "uthash.h"

typedef struct n2n_buf_s {
    char *buf;
    ssize_t size;
    struct n2n_buf_s *next, *prev;
} n2n_buf_t;

typedef struct {
    int conn_id;
    int couple_id;
    n2n_buf_t *n2n_buf_list;
    uv_timer_t *timer;
    uint64_t start_connect_tm;  // unit: millisecond
    UT_hash_handle hh;
} n2n_conn_t;

typedef struct {
    uv_loop_t *loop;
    tcp_t *tcp;
    struct sockaddr_in listen_addr;
    struct sockaddr_in target_addr;
    n2n_conn_t *n2n_conns;
    int r_keepalive;           // unit: second
    int w_keepalive;           // unit: second
    uint64_t connect_timeout;  // unit: millisecond

    char *key;
    char *iv;
} n2n_t;

n2n_t *init_n2n_server(uv_loop_t *loop, const char *listen_ip, uint16_t listen_port, const char *target_ip,
                       uint16_t target_port);
void free_n2n_server(n2n_t *n2n);
bool n2n_server_set_opts(n2n_t *n2n, int keepalive, uint64_t connect_timeout);

#endif  // N2N_SERVER_H