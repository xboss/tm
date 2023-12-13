#include "n2n_server.h"

#include "utils.h"
#include "utlist.h"

static void on_conn_timer_close(uv_handle_t *handle);
static void on_conn_timer(uv_timer_t *handle);

/* -------------------------------------------------------------------------- */
/*                                n2n protocol                                */
/* -------------------------------------------------------------------------- */

// #define N2N_MSG_CMD_DATA 0x00U
// #define N2N_MSG_CMD_AUTH 0x01U

int n2n_read_msg(const char *buf, ssize_t len, n2n_conn_t *conn, on_read_n2n_msg_t on_read_n2n_msg) {
    assert(conn);
    if (len < 0) {
        // error
        return -1;
    }
    if (len == 0) {
        // none
        return 0;
    }
    uint32_t payload_len = 0;
    uint32_t rlen = len;
    const char *p = buf;

    int tmp_buf_len = conn->msg_read_len + rlen;
    char *tmp_buf = (char *)_CALLOC(1, tmp_buf_len);
    _CHECK_OOM(tmp_buf);
    memcpy(tmp_buf, conn->msg_buf, conn->msg_read_len);
    memcpy(tmp_buf + conn->msg_read_len, p, rlen);
    _FREE_IF(conn->msg_buf);
    p = tmp_buf;
    rlen = tmp_buf_len;

    if (rlen <= N2N_MSG_HEAD_LEN) {
        // store
        goto n2n_read_msg_store;
    }

    payload_len = ntohl(*(uint32_t *)(p));
    while (rlen >= N2N_MSG_HEAD_LEN + payload_len) {
        p += N2N_MSG_HEAD_LEN;
        on_read_n2n_msg(p, payload_len, conn);
        rlen = rlen - payload_len - N2N_MSG_HEAD_LEN;
        p += payload_len;
        if (rlen <= N2N_MSG_HEAD_LEN) {
            // store
            break;
        }
        payload_len = ntohl(*(uint32_t *)(p));
        if (rlen < N2N_MSG_HEAD_LEN + payload_len) {
            break;
        }
    }

n2n_read_msg_store:
    conn->msg_buf = (char *)_CALLOC(1, rlen);
    memcpy(conn->msg_buf, p, rlen);
    _FREE_IF(tmp_buf);
    conn->msg_read_len = rlen;
    return 0;
}

char *n2n_pack_msg(const char *buf, ssize_t len, int *msg_len) {
    if (len <= 0 || !buf) {
        return NULL;
    }
    *msg_len = len + N2N_MSG_HEAD_LEN;
    char *msg = (char *)_CALLOC(1, *msg_len);
    _CHECK_OOM(msg);
    uint32_t payload_len = htonl(len);
    memcpy(msg, &payload_len, N2N_MSG_HEAD_LEN);
    memcpy(msg + N2N_MSG_HEAD_LEN, buf, len);
    return msg;
}

/* -------------------------------------------------------------------------- */
/*                             connection manager                             */
/* -------------------------------------------------------------------------- */

n2n_conn_t *n2n_get_conn(n2n_t *n2n, int conn_id) {
    if (conn_id <= 0 || !n2n || !n2n->n2n_conns) {
        return false;
    }
    n2n_conn_t *c = NULL;
    HASH_FIND_INT(n2n->n2n_conns, &conn_id, c);
    return c;
}

static bool add_conn(n2n_t *n2n, n2n_conn_t *conn) {
    if (!conn || !n2n) {
        return false;
    }
    HASH_ADD_INT(n2n->n2n_conns, conn_id, conn);
    return true;
}

static void del_conn(n2n_t *n2n, n2n_conn_t *conn) {
    if (!conn || !n2n || !n2n->n2n_conns) {
        return;
    }
    HASH_DEL(n2n->n2n_conns, conn);
}

static void free_conn(n2n_t *n2n, n2n_conn_t *conn) {
    _LOG("free n2n conn");
    if (!conn) {
        return;
    }
    assert(conn->status == N2N_CONN_ST_OFF);
    del_conn(n2n, conn);
    if (conn->timer) {
        int r = uv_timer_stop(conn->timer);
        IF_UV_ERROR(r, "n2n conn timer stop error", {});
        if (!uv_is_closing((uv_handle_t *)conn->timer)) {
            uv_close((uv_handle_t *)conn->timer, on_conn_timer_close);
        }
    }

    if (conn->n2n_buf_list) {
        n2n_buf_t *item, *tmp;
        DL_FOREACH_SAFE(conn->n2n_buf_list, item, tmp) {
            DL_DELETE(conn->n2n_buf_list, item);
            if (item->buf) {
                _FREE_IF(item->buf);
            }
            _FREE_IF(item);
        }
        conn->n2n_buf_list = NULL;
    }

    if (conn->msg_buf) {
        _FREE_IF(conn->msg_buf);
    }

    _FREE_IF(conn);
}

static n2n_conn_t *new_conn(n2n_t *n2n, int conn_id, int couple_id) {
    n2n_conn_t *n2n_conn = (n2n_conn_t *)_CALLOC(1, sizeof(n2n_conn_t));
    _CHECK_OOM(n2n_conn);
    n2n_conn->conn_id = conn_id;
    n2n_conn->couple_id = couple_id;
    n2n_conn->n2n_buf_list = NULL;
    n2n_conn->timer = NULL;
    uint64_t now = mstime();
    n2n_conn->start_connect_tm = n2n_conn->last_r_tm = now;
    n2n_conn->status = N2N_CONN_ST_OFF;
    n2n_conn->n2n = n2n;
    add_conn(n2n, n2n_conn);
    return n2n_conn;
}

/* -------------------------------------------------------------------------- */
/*                                    timer                                   */
/* -------------------------------------------------------------------------- */

typedef struct {
    uv_timer_t timer;
    int conn_id;
    int couple_id;
} timer_req_t;

static bool start_conn_timer(n2n_t *n2n, n2n_conn_t *n2n_conn) {
    assert(n2n_conn->status == N2N_CONN_ST_ON);

    timer_req_t *timer_req = (timer_req_t *)_CALLOC(1, sizeof(timer_req_t));
    _CHECK_OOM(timer_req)
    int r = uv_timer_init(n2n->loop, (uv_timer_t *)timer_req);
    IF_UV_ERROR(r, "n2n conn timer init error", {
        _FREE_IF(timer_req);
        return false;
    });
    timer_req->timer.data = n2n;
    timer_req->conn_id = n2n_conn->conn_id;
    timer_req->couple_id = n2n_conn->couple_id;
    r = uv_timer_start((uv_timer_t *)timer_req, on_conn_timer, 0, 1 * 1000);
    IF_UV_ERROR(r, "n2n conn timer start error", {
        _FREE_IF(timer_req);
        return false;
    });
    n2n_conn->timer = (uv_timer_t *)timer_req;
    return true;
}

/* -------------------------------------------------------------------------- */
/*                                  callback                                  */
/* -------------------------------------------------------------------------- */

static void on_conn_timer_close(uv_handle_t *handle) {
    _LOG("on_conn_timer_close...");
    n2n_t *n2n = (n2n_t *)handle->data;
    timer_req_t *timer_req = (timer_req_t *)handle;
    int conn_id = timer_req->conn_id;
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, { _LOG("on_conn_timer_close n2n_conn does not exist %d", conn_id); });
    if (n2n_conn) {
        n2n_close_conn(n2n, conn_id);
        assert(n2n_conn->timer);
        _FREE_IF(n2n_conn->timer);
    } else {
        _FREE_IF(handle);
    }
}

static void on_conn_timer(uv_timer_t *handle) {
    // _LOG("on_conn_timer...");
    n2n_t *n2n = (n2n_t *)handle->data;
    timer_req_t *timer_req = (timer_req_t *)handle;
    int conn_id = timer_req->conn_id;

    uint64_t now = mstime();
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, { _LOG("on_conn_timer n2n_conn does not exist %d", conn_id); });
    assert(n2n_conn);
    assert(n2n_conn->status != N2N_CONN_ST_OFF);
    if (n2n_conn && n2n_conn->start_connect_tm > 0 && now - n2n_conn->start_connect_tm > n2n->connect_timeout) {
        _LOG("on_conn_timer connect timeout %llu", now - n2n_conn->start_connect_tm);
        goto on_conn_timer_timout;
    }

    if (n2n_conn && (now - n2n_conn->last_r_tm) > n2n->r_keepalive * 1000L) {
        _LOG("on_conn_timer read timeout %llu", now - n2n_conn->last_r_tm);
        goto on_conn_timer_timout;
    }
    return;

on_conn_timer_timout:
    _LOG("timeout close %d", conn_id);
    int r = uv_timer_stop(handle);
    IF_UV_ERROR(r, "n2n conn timer stop error", {});
    if (!uv_is_closing((uv_handle_t *)handle)) {
        uv_close((uv_handle_t *)handle, on_conn_timer_close);
    }
}

static void on_front_accept(tcp_t *tcp, int conn_id) {
    _LOG("on front accept %d", conn_id);
    n2n_t *n2n = (n2n_t *)get_tcp_data(tcp);
    assert(n2n);
    int couple_id = 0;
    n2n_conn_t *n2n_conn = new_conn(n2n, conn_id, couple_id);
    n2n_conn->status = N2N_CONN_ST_ON;
    if (!start_conn_timer(n2n, n2n_conn)) {
        _LOG("on front accept start conn timer error %d", conn_id);
        n2n_close_conn(n2n, conn_id);
    }

    if (n2n->on_n2n_front_accept) {
        n2n->on_n2n_front_accept(n2n, conn_id);
    }
}

static void on_tcp_close(tcp_t *tcp, int conn_id) {
    _LOG("on tcp close %d", conn_id);
    n2n_t *n2n = (n2n_t *)get_tcp_data(tcp);
    assert(n2n);
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {
        _LOG("on_tcp_close n2n_conn does not exist %d", conn_id);
        return;
    });
    assert(n2n_conn);
    assert(n2n_conn->status != N2N_CONN_ST_OFF && n2n_conn->status != N2N_CONN_ST_CONNECTING);
    if (n2n->on_n2n_close) {
        n2n->on_n2n_close(n2n, conn_id);
    }
    n2n_conn->status = N2N_CONN_ST_OFF;
    free_conn(n2n, n2n_conn);
}

static void on_tcp_recv(tcp_t *tcp, int conn_id, const char *buf, ssize_t size) {
    _LOG("on tcp recv %d", conn_id);
    n2n_t *n2n = (n2n_t *)get_tcp_data(tcp);
    assert(n2n);
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, { _LOG("on_tcp_recv n2n_conn does not exist %d", conn_id); });
    assert(n2n_conn);
    assert(n2n_conn->status == N2N_CONN_ST_ON);

    // int rt = read_n2n_msg(buf, size, n2n_conn);
    // if (rt < 0) {
    //     _ERR( "recv error format msg  %d", conn_id);
    //     return;
    // }

    // IF_GET_TCP_CONN(tcp_conn, n2n->tcp, conn_id, {});
    // assert(tcp_conn);
    tcp_conn_mode_t conn_mode = get_tcp_conn_mode(tcp, conn_id);
    assert(conn_mode != tcp_conn_mode_none);

    if (conn_mode == tcp_conn_mode_server) {
        // front
        if (n2n->on_n2n_front_recv) {
            n2n->on_n2n_front_recv(n2n, conn_id, buf, size);
        }
    } else {
        // backend
        if (n2n->on_n2n_backend_recv) {
            n2n->on_n2n_backend_recv(n2n, conn_id, buf, size);
        }
    }

    n2n_conn->last_r_tm = mstime();
}
static void on_backend_connect(tcp_t *tcp, int conn_id) {
    _LOG("backend connect ok %d", conn_id);
    n2n_t *n2n = (n2n_t *)get_tcp_data(tcp);
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, { _LOG("on_backend_connect n2n_conn does not exist %d", conn_id); });
    assert(n2n_conn);
    assert(n2n_conn->status == N2N_CONN_ST_CONNECTING);
    n2n_conn->status = N2N_CONN_ST_ON;
    int couple_id = n2n_conn->couple_id;
    IF_GET_N2N_CONN(n2n_couple_conn, n2n, couple_id, {
        _LOG("on_backend_connect n2n_couple_conn does not exist %d", conn_id);
        n2n_close_conn(n2n, conn_id);
        return;
    });
    n2n_couple_conn->couple_id = conn_id;

    n2n_conn->start_connect_tm = 0;
    if (!start_conn_timer(n2n, n2n_conn)) {
        _LOG("on_backend_connect start conn timer error %d", conn_id);
        n2n_close_conn(n2n, conn_id);
    }

    if (n2n->on_n2n_backend_connect) {
        n2n->on_n2n_backend_connect(n2n, conn_id);
    }
}

/* -------------------------------------------------------------------------- */
/*                                 n2n server                                 */
/* -------------------------------------------------------------------------- */

static const int def_keepalive = 30;
static const uint64_t def_connect_timeout = 60000UL;

n2n_t *n2n_init_server(uv_loop_t *loop, const char *listen_ip, uint16_t listen_port, const char *target_ip,
                       uint16_t target_port, on_n2n_front_accept_t on_n2n_front_accept, on_n2n_close_t on_n2n_close,
                       on_n2n_front_recv_t on_n2n_front_recv, on_n2n_backend_recv_t on_n2n_backend_recv,
                       on_n2n_backend_connect_t on_n2n_backend_connect) {
    if (!loop || !listen_ip || listen_port <= 0) {
        return NULL;
    }
    tcp_option_t opts = {.backlog = 128, .read_buf_size = 65536};
    tcp_t *tcp = init_tcp(loop, NULL, on_front_accept, on_backend_connect, on_tcp_recv, on_tcp_close, &opts);
    if (!tcp) {
        return NULL;
    }
    struct sockaddr_in listen_sockaddr;
    int r = uv_ip4_addr(listen_ip, listen_port, &listen_sockaddr);
    IF_UV_ERROR(r, "listen ipv4 addr error", { return false; });
    struct sockaddr_in target_sockaddr;
    if (target_ip && target_port > 0) {
        r = uv_ip4_addr(target_ip, target_port, &target_sockaddr);
        IF_UV_ERROR(r, "listen ipv4 addr error", { return false; });
    }

    bool rt = start_tcp_server_with_sockaddr(tcp, listen_sockaddr);
    if (!rt) {
        free_tcp(tcp);
        return NULL;
    }
    n2n_t *n2n = (n2n_t *)_CALLOC(1, sizeof(n2n_t));
    _CHECK_OOM(n2n);
    // tcp->data = n2n;
    set_tcp_data(tcp, n2n);
    n2n->loop = loop;
    n2n->tcp = tcp;
    n2n->listen_addr = listen_sockaddr;
    n2n->target_addr = target_sockaddr;
    n2n->n2n_conns = NULL;
    n2n->r_keepalive = def_keepalive;
    n2n->w_keepalive = def_keepalive;
    n2n->connect_timeout = def_connect_timeout;
    n2n->on_n2n_front_accept = on_n2n_front_accept;
    n2n->on_n2n_close = on_n2n_close;
    n2n->on_n2n_front_recv = on_n2n_front_recv;
    n2n->on_n2n_backend_recv = on_n2n_backend_recv;
    n2n->on_n2n_backend_connect = on_n2n_backend_connect;

    return n2n;
}

void n2n_free_server(n2n_t *n2n) {
    if (!n2n) {
        return;
    }
    if (n2n->tcp) {
        stop_tcp_server(n2n->tcp);
        // free_tcp(n2n->tcp);
    }
    free(n2n);
}

bool n2n_server_set_opts(n2n_t *n2n, int keepalive, uint64_t connect_timeout) {
    if (!n2n) {
        return false;
    }
    n2n->r_keepalive = keepalive;
    n2n->w_keepalive = keepalive;
    n2n->connect_timeout = connect_timeout;
    return true;
}

int n2n_connect_backend(n2n_t *n2n, struct sockaddr_in sockaddr, int couple_id, void *data) {
    if (!n2n || !n2n->tcp || couple_id <= 0) {
        return 0;
    }

    // connect to backend
    int conn_id = connect_tcp_with_sockaddr(n2n->tcp, sockaddr, NULL);
    if (conn_id <= 0) {
        return 0;
    }
    n2n_conn_t *n2n_conn = new_conn(n2n, conn_id, couple_id);
    n2n_conn->status = N2N_CONN_ST_CONNECTING;
    n2n_conn->data = data;
    return conn_id;
}

bool n2n_send_to_front(n2n_t *n2n, int conn_id, const char *buf, ssize_t size) {
    if (!n2n || !n2n->tcp || conn_id <= 0 || !buf || size <= 0) {
        return false;
    }
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {
        _LOG("n2n_send_to_front n2n_conn does not exist %d", conn_id);
        return false;
    });
    if (n2n_conn->status != N2N_CONN_ST_ON) {
        return false;
    }
    // assert(n2n_conn->status == N2N_CONN_ST_ON);

    int rt = tcp_send(n2n->tcp, conn_id, buf, size);
    if (!rt) {
        return false;
    }
    return true;
}

bool n2n_send_to_back(n2n_t *n2n, int conn_id, const char *buf, ssize_t size) {
    if (!n2n || !n2n->tcp || conn_id <= 0) {
        return false;
    }
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {
        _LOG("n2n_send_to_back n2n_conn does not exist %d", conn_id);
        return false;
    });
    assert(n2n_conn->status != N2N_CONN_ST_OFF);

    if (buf && size > 0 && n2n_conn->status == N2N_CONN_ST_CONNECTING) {
        // maybe backend connection does not create
        n2n_buf_t *n2n_buf = (n2n_buf_t *)_CALLOC(1, sizeof(n2n_buf_t));
        _CHECK_OOM(n2n_buf);
        n2n_buf->buf = (char *)_CALLOC(1, size);
        _CHECK_OOM(n2n_buf->buf);
        memcpy(n2n_buf->buf, buf, size);
        n2n_buf->size = size;
        DL_APPEND(n2n_conn->n2n_buf_list, n2n_buf);
        // n2n_conn->last_r_tm = mstime();
        return true;
    }

    assert(n2n_conn->status == N2N_CONN_ST_ON);

    // check buf and send
    if (n2n_conn->n2n_buf_list) {
        _LOG("n2n_send_to_back buf send %d", conn_id);
        n2n_buf_t *item, *tmp;
        DL_FOREACH_SAFE(n2n_conn->n2n_buf_list, item, tmp) {
            DL_DELETE(n2n_conn->n2n_buf_list, item);
            if (item->buf) {
                int rt = tcp_send(n2n->tcp, conn_id, item->buf, item->size);
                if (!rt) {
                    return false;
                }
                _FREE_IF(item->buf);
            }
            _FREE_IF(item);
        }
        n2n_conn->n2n_buf_list = NULL;
    }

    if (buf && size > 0) {
        int rt = tcp_send(n2n->tcp, conn_id, buf, size);
        if (!rt) {
            return false;
        }
    }

    return true;
}

void n2n_close_conn(n2n_t *n2n, int conn_id) {
    _LOG("n2n_close_conn %d", conn_id);

    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {
        _LOG("n2n_close_conn n2n_conn does not exist %d", conn_id);
        return;
    });
    assert(n2n_conn->status != N2N_CONN_ST_OFF);
    n2n_conn->status = N2N_CONN_ST_CLOSING;
    close_tcp_connection(n2n->tcp, conn_id);

    int couple_id = n2n_conn->couple_id;
    if (couple_id <= 0) {
        return;
    }
    IF_GET_N2N_CONN(couple_n2n_conn, n2n, couple_id, {
        _LOG("n2n_close_conn couple_n2n_conn does not exist %d", conn_id);
        return;
    });
    couple_n2n_conn->status = N2N_CONN_ST_CLOSING;
    close_tcp_connection(n2n->tcp, couple_id);
}
