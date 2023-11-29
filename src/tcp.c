#include "tcp.h"

#include "utils.h"

#define DEF_BACKLOG 128

/* -------------------------------------------------------------------------- */
/*                             connection manager                             */
/* -------------------------------------------------------------------------- */

static tcp_connection_t *get_conn(tcp_t *tcp, int conn_id) {
    if (conn_id <= 0 || !tcp || !tcp->conns) {
        return false;
    }
    tcp_connection_t *c = NULL;
    HASH_FIND_INT(tcp->conns, &conn_id, c);
    return c;
}

static bool add_conn(tcp_t *tcp, tcp_connection_t *conn) {
    if (!conn || !tcp) {
        return false;
    }
    HASH_ADD_INT(tcp->conns, id, conn);
    return true;
}

static void del_conn(tcp_t *tcp, tcp_connection_t *conn) {
    if (!conn || !tcp || !tcp->conns) {
        return;
    }
    HASH_DEL(tcp->conns, conn);
}

/* -------------------------------------------------------------------------- */
/*                                     tcp                                    */
/* -------------------------------------------------------------------------- */

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

static void free_write_req(uv_write_t *req) {
    write_req_t *wr = (write_req_t *)req;
    _FREE_IF(wr->buf.base);
    _FREE_IF(wr);
    _LOG("free_write_req");
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *)_CALLOC(1, suggested_size);
    buf->len = suggested_size;
}

static void free_conn(tcp_connection_t *conn) {
    if (!conn) {
        return;
    }
    // TODO:
    _FREE_IF(conn);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

void close_tcp_connection(tcp_t *tcp, int conn_id) {
    if (!tcp || !tcp->conns || conn_id <= 0) {
        return;
    }
    tcp_connection_t *conn = get_conn(tcp, conn_id);
    if (!conn) {
        return;
    }

    // if (conn->status != TCP_CONN_ST_ON) {
    //     return;
    // }

    // conn->status = TCP_CONN_ST_CLOSING;

    if (!conn->cli) {
        free_conn(conn);
        return;
    }

    uv_read_stop((uv_stream_t *)conn->cli);
    uv_close((uv_handle_t *)conn->cli, on_tcp_close);
}

void free_tcp(tcp_t *tcp) {
    // TODO:
}

tcp_t *init_tcp(uv_loop_t *loop, void *data, on_tcp_accept_t on_accept, on_tcp_connect_t on_connect,
                on_tcp_recv_t on_recv, on_tcp_close_t on_close) {
    if (!loop) {
        return NULL;
    }
    tcp_t *tcp = (tcp_t *)_CALLOC(1, sizeof(tcp_t));
    _CHECK_OOM(tcp);
    tcp->conns = NULL;
    tcp->loop = loop;
    tcp->on_accept = on_accept;
    tcp->on_close = on_close;
    tcp->on_connect = on_connect;
    tcp->on_recv = on_recv;
    tcp->data = data;
    return tcp;
}

void stop_tcp_server(tcp_t *tcp) {
    // TODO:
}

bool start_tcp_server(tcp_t *tcp, const char *ip, uint16_t port) {
    if (!tcp || !ip || port <= 0) {
        return false;
    }
    int ip_len = strnlen(ip, TCP_MAX_IP_LEN + 1);
    if (ip_len >= TCP_MAX_IP_LEN + 1) {
        return false;
    }

    uv_tcp_t *serv = (uv_tcp_t *)_CALLOC(1, sizeof(uv_tcp_t));
    _CHECK_OOM(serv);
    int r = uv_tcp_init(tcp->loop, serv);
    IF_UV_ERROR(r, "init tcp server init error", {
        _FREE_IF(serv);
        return false;
    });
    struct sockaddr_in sockaddr;
    r = uv_ip4_addr(ip, port, &sockaddr);
    IF_UV_ERROR(r, "init tcp server ip4 error", {
        _FREE_IF(serv);
        return false;
    });

    r = uv_tcp_bind(serv, (const struct sockaddr *)&sockaddr, 0);
    IF_UV_ERROR(r, "init tcp server bind error", {
        _FREE_IF(serv);
        return false;
    });
    serv->data = tcp;
    r = uv_listen((uv_stream_t *)serv, DEF_BACKLOG, on_tcp_accept);
    IF_UV_ERROR(r, "init tcp server listen error", {
        _FREE_IF(serv);
        return false;
    });

    tcp->s_port = port;
    tcp->serv = serv;
    memcpy(tcp->s_ip, ip, ip_len);

    return true;
}

bool connect_tcp(tcp_t *tcp, const char *ip, uint16_t port) {
    if (!tcp || !ip || port <= 0) {
        return false;
    }
    struct sockaddr_in addr;
    int r = uv_ip4_addr(ip, port, &addr);
    IF_UV_ERROR(r, "tcp connect error", { return false; });

    uv_tcp_t *cli = (uv_tcp_t *)_CALLOC(1, sizeof(uv_tcp_t));
    _CHECK_OOM(cli);
    r = uv_tcp_init(tcp->loop, cli);
    IF_UV_ERROR(r, "tcp connect error", {
        uv_close((uv_handle_t *)cli, on_tcp_close);
        return false;
    });

    uv_connect_t *req = (uv_connect_t *)_CALLOC(1, sizeof(uv_connect_t));
    req->data = tcp;
    r = uv_tcp_connect(req, cli, (const struct sockaddr *)&addr, on_tcp_connect);
    IF_UV_ERROR(r, "tcp connect error", {
        _FREE_IF(req);
        uv_close((uv_handle_t *)cli, on_tcp_close);
        return false;
    });

    return true;
}

bool tcp_send(tcp_t *tcp, int conn_id, const char *buf, ssize_t size) {
    _LOG("tcp send %zd", size);
    if (!tcp || !tcp->conns || conn_id <= 0 || !buf || size <= 0) {
        return false;
    }

    tcp_connection_t *conn = get_conn(tcp, conn_id);
    if (!conn) {
        return false;
    }

    write_req_t *req = (write_req_t *)malloc(sizeof(write_req_t));
    char *wbuf = (char *)_CALLOC(1, size);
    memcpy(wbuf, buf, size);
    req->buf = uv_buf_init((char *)wbuf, size);

    int r = uv_write((uv_write_t *)req, (uv_stream_t *)conn->cli, &req->buf, 1, on_tcp_write);
    IF_UV_ERROR(r, "tcp send error", {
        free_write_req((uv_write_t *)req);
        close_tcp_connection(conn);
        return false;
    });
    return true;
}

tcp_connection_t *get_tcp_connection(tcp_t *tcp, int conn_id) { return get_conn(tcp, conn_id); }
