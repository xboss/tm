#include "n2n_server.h"

#include "utils.h"
#include "utlist.h"

#define IF_GET_N2N_CONN(_V_CONN, _V_N2N, _V_CONN_ID, _ACT)      \
    n2n_conn_t *(_V_CONN) = get_conn((_V_N2N), (_V_CONN_ID));   \
    if (!(_V_CONN)) {                                           \
        _LOG("n2n connection does not exist %d", (_V_CONN_ID)); \
        _ACT                                                    \
    }

typedef struct {
    uv_timer_t timer;
    int conn_id;
    int couple_id;
} timer_req_t;

/* -------------------------------------------------------------------------- */
/*                             connection manager                             */
/* -------------------------------------------------------------------------- */
static void close_n2n_conn(n2n_t *n2n, int conn_id);

static n2n_conn_t *get_conn(n2n_t *n2n, int conn_id) {
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

void on_conn_timer_close(uv_handle_t *handle) {
    _LOG("on_conn_timer_close...");
    n2n_t *n2n = (n2n_t *)handle->data;
    timer_req_t *timer_req = (timer_req_t *)handle;
    int conn_id = timer_req->conn_id;
    // IF_GET_TCP_CONN(tcp_conn, n2n->tcp, conn_id, { return; });
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {});
    if (n2n_conn) {
        close_n2n_conn(n2n, conn_id);
        assert(n2n_conn->timer);
        _FREE_IF(n2n_conn->timer);
    } else {
        _FREE_IF(handle);
    }
    // assert(n2n_conn);
    // if (n2n_conn->timer) {
    //     _FREE_IF(n2n_conn->timer);
    // }
    // close_n2n_conn(n2n, conn_id);
    // _FREE_IF(handle);
}

static void free_conn(n2n_t *n2n, n2n_conn_t *conn) {
    _LOG("free n2n conn");
    if (!conn) {
        return;
    }
    del_conn(n2n, conn);
    if (conn->timer) {
        int r = uv_timer_stop(conn->timer);
        IF_UV_ERROR(r, "n2n conn timer stop error", {});
        if (!uv_is_closing((uv_handle_t *)conn->timer)) {
            uv_close((uv_handle_t *)conn->timer, on_conn_timer_close);
        }
        // conn->timer = NULL;
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
    _FREE_IF(conn);
}

static void close_n2n_conn(n2n_t *n2n, int conn_id) {
    _LOG("close_n2n_conn %d", conn_id);

    // IF_GET_TCP_CONN(tcp_conn, n2n->tcp, conn_id, {});
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {
        _LOG("close_n2n_conn n2n_conn does not exist %d", conn_id);
        return;
    });

    close_tcp_connection(n2n->tcp, conn_id);

    int couple_id = n2n_conn->couple_id;
    assert(couple_id > 0);
    // IF_GET_TCP_CONN(couple_tcp_conn, n2n->tcp, couple_id, {});
    IF_GET_N2N_CONN(couple_n2n_conn, n2n, couple_id, {
        _LOG("close_n2n_conn couple_n2n_conn does not exist %d", conn_id);
        return;
    });
    close_tcp_connection(n2n->tcp, couple_id);

    // assert(couple_n2n_conn);
    // if (couple_tcp_conn) {
    //     close_tcp_connection(n2n->tcp, couple_id);
    // }
}

static void on_conn_timer(uv_timer_t *handle) {
    _LOG("on_conn_timer...");
    n2n_t *n2n = (n2n_t *)handle->data;
    timer_req_t *timer_req = (timer_req_t *)handle;
    int conn_id = timer_req->conn_id;

    uint64_t now = mstime();
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {});
    if (n2n_conn && n2n_conn->start_connect_tm > 0 && now - n2n_conn->start_connect_tm > n2n->connect_timeout) {
        _LOG("on_conn_timer connect timeout %llu", now - n2n_conn->start_connect_tm);
        goto on_conn_timer_timout;
    }

    IF_GET_TCP_CONN(tcp_conn, n2n->tcp, conn_id, { assert(tcp_conn); });
    if ((now - tcp_conn->last_r_tm) > n2n->r_keepalive * 1000L) {
        _LOG("on_conn_timer read timeout %llu", now - tcp_conn->last_r_tm);
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

static bool start_conn_timer(n2n_t *n2n, n2n_conn_t *n2n_conn) {
    timer_req_t *timer_req = (timer_req_t *)_CALLOC(1, sizeof(timer_req_t));
    _CHECK_OOM(timer_req)
    int r = uv_timer_init(n2n->loop, (uv_timer_t *)timer_req);
    IF_UV_ERROR(r, "n2n conn timer init error", {
        _FREE_IF(timer_req);
        // free_conn(n2n, n2n_conn);
        // return NULL;
        return false;
    });
    timer_req->timer.data = n2n;
    timer_req->conn_id = n2n_conn->conn_id;
    timer_req->couple_id = n2n_conn->couple_id;
    r = uv_timer_start((uv_timer_t *)timer_req, on_conn_timer, 0, 1 * 1000);
    IF_UV_ERROR(r, "n2n conn timer start error", {
        _FREE_IF(timer_req);
        // free_conn(n2n, n2n_conn);
        // return NULL;
        return false;
    });
    n2n_conn->timer = (uv_timer_t *)timer_req;
    return true;
}

static n2n_conn_t *new_conn(n2n_t *n2n, int conn_id, int couple_id) {
    n2n_conn_t *n2n_conn = (n2n_conn_t *)_CALLOC(1, sizeof(n2n_conn_t));
    _CHECK_OOM(n2n_conn);
    n2n_conn->conn_id = conn_id;
    n2n_conn->couple_id = couple_id;
    n2n_conn->n2n_buf_list = NULL;
    n2n_conn->timer = NULL;
    n2n_conn->start_connect_tm = mstime();

    // timer_req_t *timer_req = (timer_req_t *)_CALLOC(1, sizeof(timer_req_t));
    // _CHECK_OOM(timer_req)
    // int r = uv_timer_init(n2n->loop, (uv_timer_t *)timer_req);
    // IF_UV_ERROR(r, "n2n conn timer init error", {
    //     _FREE_IF(timer_req);
    //     free_conn(n2n, n2n_conn);
    //     return NULL;
    // });
    // timer_req->timer.data = n2n;
    // timer_req->conn_id = conn_id;
    // timer_req->couple_id = couple_id;
    // r = uv_timer_start((uv_timer_t *)timer_req, on_conn_timer, 0, 1 * 1000);
    // IF_UV_ERROR(r, "n2n conn timer start error", {
    //     _FREE_IF(timer_req);
    //     free_conn(n2n, n2n_conn);
    //     return NULL;
    // });
    // n2n_conn->timer = (uv_timer_t *)timer_req;

    add_conn(n2n, n2n_conn);
    return n2n_conn;
}

/* -------------------------------------------------------------------------- */
/*                                  callback                                  */
/* -------------------------------------------------------------------------- */

static void on_front_accept(tcp_t *tcp, int conn_id) {
    _LOG("on front accept %d", conn_id);
    // IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    n2n_t *n2n = (n2n_t *)tcp->data;
    assert(n2n);

    // connect to backend
    int couple_id = connect_tcp_with_sockaddr(tcp, n2n->target_addr, NULL);
    if (couple_id <= 0) {
        // error
        close_n2n_conn(n2n, conn_id);
    }
    n2n_conn_t *n2n_conn = new_conn(n2n, conn_id, couple_id);
    new_conn(n2n, couple_id, conn_id);
    if (!start_conn_timer(n2n, n2n_conn)) {
        _LOG("on front accept start conn timer error %d", conn_id);
        close_n2n_conn(n2n, conn_id);
    }
}

static void on_tcp_close(tcp_t *tcp, int conn_id) {
    _LOG("on tcp close %d", conn_id);
    n2n_t *n2n = (n2n_t *)tcp->data;
    assert(n2n);
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, { return; });
    assert(n2n_conn);
    free_conn(n2n, n2n_conn);
    // if (conn_id == n2n_conn->conn_id) {
    //     n2n_conn->conn_id = 0;
    // }
    // if (conn_id == n2n_conn->couple_id) {
    //     n2n_conn->couple_id = 0;
    // }
    // if (n2n_conn->conn_id == 0 && n2n_conn->couple_id == 0) {
    // }
}

static void on_tcp_recv(tcp_t *tcp, int conn_id, const char *buf, ssize_t size) {
    _LOG("on tcp recv %d", conn_id);
    // IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    n2n_t *n2n = (n2n_t *)tcp->data;
    assert(n2n);
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {
        close_n2n_conn(n2n, conn_id);
        return;
    });

    int couple_id = n2n_conn->couple_id;
    IF_GET_TCP_CONN(couple_tcp_conn, tcp, couple_id, {
        // TODO: couple conn可能会连接失败
        // maybe backend connection does not create
        n2n_buf_t *n2n_buf = (n2n_buf_t *)_CALLOC(1, sizeof(n2n_buf_t));
        _CHECK_OOM(n2n_buf);
        n2n_buf->buf = (char *)_CALLOC(1, size);
        _CHECK_OOM(n2n_buf->buf);
        memcpy(n2n_buf->buf, buf, size);
        n2n_buf->size = size;
        DL_APPEND(n2n_conn->n2n_buf_list, n2n_buf);
        return;
    });

    // send to couple
    int rt = tcp_send(tcp, couple_id, buf, size);
    if (!rt) {
        close_n2n_conn(n2n, conn_id);
        return;
    }
}
static void on_back_connect(tcp_t *tcp, int conn_id) {
    _LOG("back connect ok %d", conn_id);
    // IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    n2n_t *n2n = (n2n_t *)tcp->data;
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {
        close_n2n_conn(n2n, conn_id);
        return;
    });
    int couple_id = n2n_conn->couple_id;
    IF_GET_N2N_CONN(n2n_cp_conn, n2n, couple_id, {
        close_n2n_conn(n2n, conn_id);
        return;
    });

    n2n_conn->start_connect_tm = 0;
    if (!start_conn_timer(n2n, n2n_conn)) {
        _LOG("on_back_connect start conn timer error %d", conn_id);
        close_n2n_conn(n2n, conn_id);
    }

    // check buf and send
    if (n2n_cp_conn->n2n_buf_list) {
        _LOG("back connect couple send %d from %d", couple_id, conn_id);
        n2n_buf_t *item, *tmp;
        DL_FOREACH_SAFE(n2n_cp_conn->n2n_buf_list, item, tmp) {
            DL_DELETE(n2n_cp_conn->n2n_buf_list, item);
            if (item->buf) {
                int rt = tcp_send(tcp, conn_id, item->buf, item->size);
                if (!rt) {
                    close_n2n_conn(n2n, conn_id);
                    return;
                }
                _FREE_IF(item->buf);
            }
            _FREE_IF(item);
        }
        n2n_conn->n2n_buf_list = NULL;
    }
}

/* -------------------------------------------------------------------------- */
/*                                 n2n server                                 */
/* -------------------------------------------------------------------------- */

static const int def_keepalive = 30;
static const uint64_t def_connect_timeout = 60000UL;

n2n_t *init_n2n_server(uv_loop_t *loop, const char *listen_ip, uint16_t listen_port, const char *target_ip,
                       uint16_t target_port) {
    if (!loop || !listen_ip || listen_port <= 0 || !target_ip || target_port <= 0) {
        return NULL;
    }
    tcp_t *tcp = init_tcp(loop, NULL, on_front_accept, on_back_connect, on_tcp_recv, on_tcp_close);
    if (!tcp) {
        return NULL;
    }
    struct sockaddr_in listen_sockaddr;
    int r = uv_ip4_addr(listen_ip, listen_port, &listen_sockaddr);
    IF_UV_ERROR(r, "listen ipv4 addr error", { return false; });
    struct sockaddr_in target_sockaddr;
    r = uv_ip4_addr(target_ip, target_port, &target_sockaddr);
    IF_UV_ERROR(r, "listen ipv4 addr error", { return false; });
    bool rt = start_tcp_server_with_sockaddr(tcp, listen_sockaddr);
    if (!rt) {
        free_tcp(tcp);
        return NULL;
    }
    n2n_t *n2n = (n2n_t *)_CALLOC(1, sizeof(n2n_t));
    _CHECK_OOM(n2n);
    tcp->data = n2n;
    n2n->loop = loop;
    n2n->tcp = tcp;
    n2n->listen_addr = listen_sockaddr;
    n2n->target_addr = target_sockaddr;
    n2n->n2n_conns = NULL;
    n2n->r_keepalive = def_keepalive;
    n2n->w_keepalive = def_keepalive;
    n2n->connect_timeout = def_connect_timeout;

    return n2n;
}

void free_n2n_server(n2n_t *n2n) {
    if (!n2n) {
        return;
    }
    if (n2n->tcp) {
        stop_tcp_server(n2n->tcp);
        free_tcp(n2n->tcp);
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
