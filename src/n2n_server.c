#include "n2n_server.h"

#include "utils.h"
#include "utlist.h"

#define IF_GET_N2N_CONN(_V_CONN, _V_N2N, _V_CONN_ID, _ACT)      \
    n2n_conn_t *(_V_CONN) = get_conn((_V_N2N), (_V_CONN_ID));   \
    if (!(_V_CONN)) {                                           \
        _LOG("n2n connection does not exist %d", (_V_CONN_ID)); \
        _ACT                                                    \
    }

/* -------------------------------------------------------------------------- */
/*                             connection manager                             */
/* -------------------------------------------------------------------------- */

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

static void free_conn(n2n_t *n2n, n2n_conn_t *conn) {
    if (!conn) {
        return;
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
    }
    del_conn(n2n, conn);
    _FREE_IF(conn);
}

static n2n_conn_t *new_conn(n2n_t *n2n, int conn_id, int couple_id) {
    n2n_conn_t *n2n_conn = (n2n_conn_t *)_CALLOC(1, sizeof(n2n_conn_t));
    n2n_conn->conn_id = conn_id;
    n2n_conn->couple_id = couple_id;
    n2n_conn->n2n_buf_list = NULL;
    add_conn(n2n, n2n_conn);
    return n2n_conn;
}

static void close_n2n_conn(n2n_t *n2n, int conn_id) {
    _LOG("close_n2n_conn %d", conn_id);

    IF_GET_TCP_CONN(tcp_conn, n2n->tcp, conn_id, {});
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {});

    if (!tcp_conn && !n2n_conn) {
        return;
    }

    if (tcp_conn && !n2n_conn) {
        // close_tcp_connection(n2n->tcp, conn_id);
        return;
    }

    if (!tcp_conn && n2n_conn) {
        free_conn(n2n, n2n_conn);
        return;
    }

    int couple_id = n2n_conn->couple_id;
    if (couple_id <= 0) {
        _LOG("%d does not have couple  %d", conn_id, couple_id);
        return;
    }
    free_conn(n2n, n2n_conn);

    IF_GET_TCP_CONN(couple_tcp_conn, n2n->tcp, couple_id, {});
    IF_GET_N2N_CONN(couple_n2n_conn, n2n, couple_id, {});

    if (!couple_tcp_conn && !couple_n2n_conn) {
        return;
    }

    if (couple_tcp_conn && !couple_n2n_conn) {
        close_tcp_connection(n2n->tcp, couple_id);
        return;
    }

    if (!couple_tcp_conn && couple_n2n_conn) {
        free_conn(n2n, couple_n2n_conn);
        return;
    }
    free_conn(n2n, couple_n2n_conn);
}

/* -------------------------------------------------------------------------- */
/*                                  callback                                  */
/* -------------------------------------------------------------------------- */

static void on_front_accept(tcp_t *tcp, int conn_id) {
    _LOG("on front accept %d", conn_id);
    IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    n2n_t *n2n = (n2n_t *)tcp->data;
    assert(n2n);

    int *p_conn_id = (int *)_CALLOC(1, sizeof(int));
    _CHECK_OOM(p_conn_id);
    *p_conn_id = conn_id;
    // connect to backend
    if (!connect_tcp_with_sockaddr(tcp, n2n->target_addr, p_conn_id)) {
        // error
        close_n2n_conn(n2n, conn_id);
    }
    new_conn(n2n, conn_id, 0);
}

static void on_tcp_close(tcp_t *tcp, int conn_id) {
    _LOG("on tcp close %d", conn_id);
    n2n_t *n2n = (n2n_t *)tcp->data;
    assert(n2n);
    // IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    close_n2n_conn(n2n, conn_id);
}

static void on_tcp_recv(tcp_t *tcp, int conn_id, const char *buf, ssize_t size) {
    _LOG("on tcp recv %d", conn_id);
    IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    n2n_t *n2n = (n2n_t *)tcp->data;
    assert(n2n);
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {
        close_n2n_conn(n2n, conn_id);
        return;
    });

    int couple_id = n2n_conn->couple_id;
    if (couple_id <= 0) {
        // maybe backend connection does not create
        n2n_buf_t *n2n_buf = (n2n_buf_t *)_CALLOC(1, sizeof(n2n_buf_t));
        _CHECK_OOM(n2n_buf);
        n2n_buf->buf = (char *)_CALLOC(1, size);
        _CHECK_OOM(n2n_buf->buf);
        memcpy(n2n_buf->buf, buf, size);
        n2n_buf->size = size;
        DL_APPEND(n2n_conn->n2n_buf_list, n2n_buf);
        return;
    }

    IF_GET_TCP_CONN(couple_conn, tcp, couple_id, {
        close_n2n_conn(n2n, conn_id);
        return;
    });

    // int rt = 0;
    // // check buf and send
    // if (n2n_conn->n2n_buf_list) {
    //     n2n_buf_t *item, *tmp;
    //     DL_FOREACH_SAFE(n2n_conn->n2n_buf_list, item, tmp) {
    //         DL_DELETE(n2n_conn->n2n_buf_list, item);
    //         if (item->buf) {
    //             rt = tcp_send(tcp, couple_id, item->buf, item->size);
    //             if (!rt) {
    //                 close_n2n_conn(n2n, conn_id);
    //                 return;
    //             }
    //             _FREE_IF(item->buf);
    //         }
    //         _FREE_IF(item);
    //     }
    //     n2n_conn->n2n_buf_list = NULL;
    // }

    // send to couple
    int rt = tcp_send(tcp, couple_id, buf, size);
    if (!rt) {
        close_n2n_conn(n2n, conn_id);
        return;
    }
}
static void on_back_connect(tcp_t *tcp, int conn_id) {
    _LOG("back connect ok %d", conn_id);
    IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    int couple_id = *(int *)tcp_conn->data;
    _FREE_IF(tcp_conn->data);
    tcp_conn->data = NULL;
    n2n_t *n2n = (n2n_t *)tcp->data;
    IF_GET_N2N_CONN(n2n_conn, n2n, couple_id, {
        close_n2n_conn(n2n, conn_id);
        return;
    });
    n2n_conn->couple_id = conn_id;
    new_conn(n2n, conn_id, couple_id);
    _LOG("back connect create couple %d %d", conn_id, couple_id);

    // check buf and send
    if (n2n_conn->n2n_buf_list) {
        _LOG("back connect couple send %d from %d", couple_id, conn_id);
        n2n_buf_t *item, *tmp;
        DL_FOREACH_SAFE(n2n_conn->n2n_buf_list, item, tmp) {
            DL_DELETE(n2n_conn->n2n_buf_list, item);
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
