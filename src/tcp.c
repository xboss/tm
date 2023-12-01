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
    uv_connect_t req;
    void *data;
    tcp_t *tcp;
    struct sockaddr_in addr;
    uint16_t port;
} connect_req_t;

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
    tcp_t *tcp = conn->tcp;
    assert(tcp);
    del_conn(tcp, conn);
    _FREE_IF(conn);
}

static void on_tcp_close(uv_handle_t *handle) {
    _LOG("on_tcp_close");

    int r = uv_read_stop((uv_stream_t *)handle);
    IF_UV_ERROR(r, "stop read error when on close connection", {});

    tcp_connection_t *conn = (tcp_connection_t *)handle->data;
    if (!conn) {
        _LOG("on_tcp_close error");
        goto on_uv_close_end;
    }
    tcp_t *tcp = conn->tcp;
    assert(tcp);

    if (tcp->on_close) {
        tcp->on_close(tcp, conn->id);
    }
    free_conn(conn);
    _LOG("on_tcp_close ok %d", conn->id);

on_uv_close_end:
    // conn->status = TCP_CONN_ST_OFF;
    _FREE_IF(handle);
}

static void on_tcp_shutdown(uv_shutdown_t *req, int status) {
    tcp_t *tcp = (tcp_t *)req->data;
    assert(tcp);
    if (tcp->conns) {
        tcp_connection_t *conn, *tmp;
        HASH_ITER(hh, tcp->conns, conn, tmp) { close_tcp_connection(tcp, conn->id); }
    }
    _FREE_IF(req);
}

static void on_tcp_write(uv_write_t *req, int status) {
    _LOG("on_tcp_write");

    if (status == UV_ECANCELED) {
        // connection has been closed
        _LOG("connection has been closed when writing");
        free_write_req(req);
        return;
    }

    // uv_tcp_t *cli = (uv_tcp_t *)req->handle;
    // assert(cli);
    tcp_connection_t *conn = (tcp_connection_t *)req->data;
    assert(conn);
    tcp_t *tcp = conn->tcp;
    assert(tcp);

    IF_UV_ERROR(status, "tcp write error", { close_tcp_connection(tcp, conn->id); });
    free_write_req(req);
    _LOG("on_tcp_write id: %d", conn->id);
}

static void on_tcp_read(uv_stream_t *cli, ssize_t nread, const uv_buf_t *buf) {
    _LOG("on_tcp_read");

    tcp_connection_t *conn = (tcp_connection_t *)cli->data;
    assert(conn);
    tcp_t *tcp = conn->tcp;
    assert(tcp);
    if (nread > 0) {
        if (tcp->on_recv) {
            tcp->on_recv(tcp, conn->id, buf->base, nread);
        }
    }
    if (nread < 0) {
        if (nread != UV_EOF) fprintf(stderr, "tcp read error %s\n", uv_err_name(nread));
        close_tcp_connection(tcp, conn->id);
    }
    // _LOG("read n:%ld", nread);

    free(buf->base);
    // _LOG("free buf base");
    _LOG("on_tcp_read id: %d n: %ld", conn->id, nread);
}

// inline static int *init_id_pointer(int id) {
//     int *p_id = (int *)_CALLOC(1, sizeof(id));
//     _CHECK_OOM(p_id);
//     return p_id;
// }

// inline static void free_id_pointer(int *p_id) { _FREE_IF(p_id); }

// inline static int deref_id(void *data) {
//     int id = *(int *)data;
//     return id;
// }

static tcp_connection_t *init_conn(int id, uv_tcp_t *cli, tcp_t *tcp, char mode, void *data) {
    if (!cli || !tcp || id <= 0) {
        return NULL;
    }
    tcp_connection_t *conn = (tcp_connection_t *)_CALLOC(1, sizeof(tcp_connection_t));
    _CHECK_OOM(conn);
    conn->id = id;
    conn->tcp = tcp;
    conn->cli = cli;
    conn->data = data;
    conn->mode = mode;

    // cli->data = init_id_pointer(conn->id);
    cli->data = conn;
    int r = uv_read_start((uv_stream_t *)cli, alloc_buffer, on_tcp_read);
    IF_UV_ERROR(r, "tcp start read error", {
        // free_id_pointer((int *)cli->data);
        free_conn(conn);
        return NULL;
    });
    // conn->status = TCP_CONN_ST_ON;
    return conn;
}

static void on_tcp_connect(uv_connect_t *req, int status) {
    _LOG("on_tcp_accept");
    uv_tcp_t *cli = (uv_tcp_t *)req->handle;
    assert(cli);
    connect_req_t *connect_req = (connect_req_t *)req;

    IF_UV_ERROR(status, "tcp client connect error", {
        _FREE_IF(req);
        // _FREE_IF(cli);
        uv_close((uv_handle_t *)cli, on_tcp_close);
        return;
    });
    tcp_t *tcp = connect_req->tcp;
    assert(tcp);
    tcp_connection_t *conn = init_conn(tcp->cid++, cli, tcp, TCP_CONN_MODE_CLI, connect_req->data);
    if (!conn) {
        _FREE_IF(req);
        uv_close((uv_handle_t *)cli, on_tcp_close);
        return;
    }
    conn->c_addr = connect_req->addr;
    conn->c_port = connect_req->port;
    add_conn(tcp, conn);
    if (tcp->on_connect) {
        tcp->on_connect(tcp, conn->id);
    }
    _FREE_IF(req);
    _LOG("on_tcp_accept id: %d", conn->id);
}

static void on_tcp_accept(uv_stream_t *server, int status) {
    _LOG("on_tcp_accept");
    IF_UV_ERROR(status, "new tcp server connection error", { return; });
    uv_tcp_t *cli = (uv_tcp_t *)_CALLOC(1, sizeof(uv_tcp_t));
    _CHECK_OOM(cli);
    int r = uv_tcp_init(server->loop, cli);
    IF_UV_ERROR(r, "new tcp server connection error", {
        _FREE_IF(cli);
        return;
    });
    tcp_t *tcp = (tcp_t *)server->data;
    r = uv_accept(server, (uv_stream_t *)cli);
    IF_UV_ERROR(r, "accept tcp server connection error", {
        _FREE_IF(cli);
        return;
    });
    tcp_connection_t *conn = init_conn(tcp->cid++, cli, tcp, TCP_CONN_MODE_SERV, NULL);
    if (!conn) {
        fprintf(stderr, "init tcp connection error");
        _FREE_IF(cli);
        return;
    }
    add_conn(tcp, conn);
    if (tcp->on_accept) {
        tcp->on_accept(tcp, conn->id);
    }
    _LOG("on_tcp_accept id: %d", conn->id);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

void close_tcp_connection(tcp_t *tcp, int conn_id) {
    _LOG("close_tcp_connection %d", conn_id);
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

    int r = uv_read_stop((uv_stream_t *)conn->cli);
    IF_UV_ERROR(r, "stop read error when closing connection", {});
    uv_close((uv_handle_t *)conn->cli, on_tcp_close);
    _LOG("close_tcp_connection end %d", conn_id);
}

void free_tcp(tcp_t *tcp) {
    if (!tcp) {
        return;
    }
    _FREE_IF(tcp);
}

tcp_t *init_tcp(uv_loop_t *loop, void *data, on_tcp_accept_t on_accept, on_tcp_connect_t on_connect,
                on_tcp_recv_t on_recv, on_tcp_close_t on_close) {
    if (!loop) {
        return NULL;
    }
    tcp_t *tcp = (tcp_t *)_CALLOC(1, sizeof(tcp_t));
    _CHECK_OOM(tcp);
    tcp->cid = 1;
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
    if (!tcp) {
        return;
    }

    if (!tcp->serv) {
        free_tcp(tcp);
        return;
    }

    int r = uv_read_stop((uv_stream_t *)tcp->serv);
    IF_UV_ERROR(r, "tcp server stop read error", {});
    uv_shutdown_t *req = (uv_shutdown_t *)_CALLOC(1, sizeof(uv_shutdown));
    req->data = tcp;
    r = uv_shutdown(req, (uv_stream_t *)tcp->serv, on_tcp_shutdown);
    IF_UV_ERROR(r, "tcp server shutdown error", {
        if (tcp->conns) {
            tcp_connection_t *conn;
            tcp_connection_t *tmp;
            HASH_ITER(hh, tcp->conns, conn, tmp) { close_tcp_connection(tcp, conn->id); }
        }
    });
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
    tcp->s_addr = sockaddr;

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
    // memcpy(tcp->s_ip, ip, ip_len);

    _LOG("Tcp server is started %s %u", ip, port);
    return true;
}

bool connect_tcp(tcp_t *tcp, const char *ip, uint16_t port, void *data) {
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

    // uv_connect_t *req = (uv_connect_t *)_CALLOC(1, sizeof(uv_connect_t));
    // req->data = tcp;
    // cli->data = data;

    connect_req_t *connect_req = (connect_req_t *)_CALLOC(1, sizeof(connect_req_t));
    connect_req->data = data;
    connect_req->addr = addr;
    connect_req->port = port;
    connect_req->tcp = tcp;
    r = uv_tcp_connect((uv_connect_t *)connect_req, cli, (const struct sockaddr *)&addr, on_tcp_connect);
    IF_UV_ERROR(r, "tcp connect error", {
        _FREE_IF(connect_req);
        uv_close((uv_handle_t *)cli, on_tcp_close);
        return false;
    });

    return true;
}

bool tcp_send(tcp_t *tcp, int conn_id, const char *buf, ssize_t size) {
    _LOG("tcp send %zd", size);
    if (!tcp || conn_id <= 0 || !buf || size <= 0) {
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
    req->req.data = conn;

    int r = uv_write((uv_write_t *)req, (uv_stream_t *)conn->cli, &req->buf, 1, on_tcp_write);
    IF_UV_ERROR(r, "tcp send error", {
        free_write_req((uv_write_t *)req);
        close_tcp_connection(tcp, conn->id);
        return false;
    });
    return true;
}

tcp_connection_t *get_tcp_connection(tcp_t *tcp, int conn_id) { return get_conn(tcp, conn_id); }
