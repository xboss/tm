#ifndef _N2N_SERVER_H
#define _N2N_SERVER_H

#include <stdbool.h>
#include <uv.h>

#include "tcp.h"
#include "uthash.h"

#define N2N_CONN_ST_OFF 0
#define N2N_CONN_ST_ON 1
#define N2N_CONN_ST_CONNECTING 2
#define N2N_CONN_ST_CLOSING 3

#define N2N_MSG_HEAD_LEN 4

#define IF_GET_N2N_CONN(_V_CONN, _V_N2N, _V_CONN_ID, _ACT)        \
    n2n_conn_t *(_V_CONN) = n2n_get_conn((_V_N2N), (_V_CONN_ID)); \
    if (!(_V_CONN)) {                                             \
        _ACT                                                      \
    }

typedef struct n2n_conn_s n2n_conn_t;
typedef struct n2n_s n2n_t;

typedef void (*on_n2n_front_accept_t)(n2n_t *n2n, int conn_id);
typedef void (*on_n2n_close_t)(n2n_t *n2n, int conn_id);
typedef void (*on_n2n_front_recv_t)(n2n_t *n2n, int conn_id, const char *buf, ssize_t size);
typedef void (*on_n2n_backend_recv_t)(n2n_t *n2n, int conn_id, const char *buf, ssize_t size);
typedef void (*on_n2n_backend_connect_t)(n2n_t *n2n, int conn_id);
typedef void (*on_read_n2n_msg_t)(const char *buf, ssize_t len, n2n_conn_t *conn);

typedef struct n2n_buf_s {
    char *buf;
    ssize_t size;
    struct n2n_buf_s *next, *prev;
} n2n_buf_t;

struct n2n_conn_s {
    int conn_id;
    int couple_id;
    n2n_buf_t *n2n_buf_list;
    uv_timer_t *timer;
    uint64_t start_connect_tm; /* unit: millisecond */
    int status;
    uint64_t last_r_tm;
    uint64_t last_w_tm;
    void *data;
    n2n_t *n2n;

    uint32_t msg_read_len;
    char *msg_buf;

    UT_hash_handle hh;
};

struct n2n_s {
    uv_loop_t *loop;
    tcp_t *tcp;
    struct sockaddr_in listen_addr;
    struct sockaddr_in target_addr;
    n2n_conn_t *n2n_conns;
    int r_keepalive;          /* unit: second */
    int w_keepalive;          /* unit: second */
    uint64_t connect_timeout; /* unit: millisecond */
    void *data;

    on_n2n_front_accept_t on_n2n_front_accept;
    on_n2n_close_t on_n2n_close;
    on_n2n_front_recv_t on_n2n_front_recv;
    on_n2n_backend_recv_t on_n2n_backend_recv;
    on_n2n_backend_connect_t on_n2n_backend_connect;
};

n2n_t *n2n_init_server(uv_loop_t *loop, const char *listen_ip, uint16_t listen_port, const char *target_ip,
                       uint16_t target_port, on_n2n_front_accept_t on_n2n_front_accept, on_n2n_close_t on_n2n_close,
                       on_n2n_front_recv_t on_n2n_front_recv, on_n2n_backend_recv_t on_n2n_backend_recv,
                       on_n2n_backend_connect_t on_n2n_backend_connect);
void n2n_free_server(n2n_t *n2n);
bool n2n_server_set_opts(n2n_t *n2n, int r_keepalive, int w_keepalive, uint64_t connect_timeout);
int n2n_connect_backend(n2n_t *n2n, struct sockaddr_in sockaddr, int couple_id, void *data);
bool n2n_send_to_front(n2n_t *n2n, int conn_id, const char *buf, ssize_t size);
bool n2n_send_to_back(n2n_t *n2n, int conn_id, const char *buf, ssize_t size);
n2n_conn_t *n2n_get_conn(n2n_t *n2n, int conn_id);
void n2n_close_conn(n2n_t *n2n, int conn_id);

/*
format: remain_length(4B)payload(nB)
*/
int n2n_read_msg(const char *buf, ssize_t len, n2n_conn_t *conn, on_read_n2n_msg_t on_read_n2n_msg);
char *n2n_pack_msg(const char *buf, ssize_t len, int *msg_len);

#endif /* N2N_SERVER_H */