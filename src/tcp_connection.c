#include "tcp_connection.h"

#include "utils.h"

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct {
    uv_connect_t req;
    void *data;
    // on_tcp_accept_t on_accept;
    on_tcp_connect_t on_connect;
    on_tcp_recv_t on_recv;
    on_tcp_close_t on_close;
} connect_req_t;

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
    _FREE_IF(conn);
}

static void on_uv_close(uv_handle_t *handle) {
    _LOG("on_uv_close");
    tcp_connection_t *conn = (tcp_connection_t *)handle->data;
    if (!conn) {
        goto on_uv_close_end;
    }

    if (conn->on_close) {
        conn->on_close(conn);
    }
    free_conn(conn);

on_uv_close_end:
    _FREE_IF(handle);
}

static void on_uv_write(uv_write_t *req, int status) {
    _LOG("on_uv_write");
    IF_UV_ERROR(status, "tcp write error", {});
    free_write_req(req);
}

static void on_uv_read(uv_stream_t *cli, ssize_t nread, const uv_buf_t *buf) {
    _LOG("on_uv_read");
    if (nread > 0) {
        tcp_connection_t *conn = (tcp_connection_t *)cli->data;
        if (conn && conn->on_recv) {
            conn->on_recv(conn, buf->base, nread);
        }
        // return;
    }
    if (nread < 0) {
        if (nread != UV_EOF) fprintf(stderr, "tcp read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t *)cli, on_uv_close);
    }

    free(buf->base);
    _LOG("free buf base");
}

static void on_uv_connect(uv_connect_t *req, int status) {
    // tcp_connection_t *conn = (tcp_connection_t *)req->data;

    IF_UV_ERROR(status, "tcp client connect error", {
        // close_tcp_connection(conn);
        _FREE_IF(req);
        return;
    });

    connect_req_t *connect_req = (connect_req_t *)req;

    uv_tcp_t *cli = (uv_tcp_t *)req->handle;
    tcp_connection_t *conn = init_tcp_connection(cli->accepted_fd, cli, NULL, connect_req->data,
                                                 connect_req->on_connect, connect_req->on_recv, connect_req->on_close);
    if (!conn) {
        _FREE_IF(req);
        uv_close((uv_handle_t *)cli, on_uv_close);
        return;
    }

    if (conn->on_connect) {
        conn->on_connect(conn);
    }

    _FREE_IF(req);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

tcp_connection_t *init_tcp_connection(int id, uv_tcp_t *cli, tcp_server_t *serv, void *data,
                                      on_tcp_connect_t on_connect, on_tcp_recv_t on_recv, on_tcp_close_t on_close) {
    if (!cli) {
        return NULL;
    }

    tcp_connection_t *conn = (tcp_connection_t *)_CALLOC(1, sizeof(tcp_connection_t));
    _CHECK_OOM(conn);
    cli->data = conn;
    // conn->tcp = tcp;
    conn->id = id;
    conn->serv = serv;
    conn->cli = cli;
    conn->data = data;
    // conn->on_accept = on_accept;
    conn->on_connect = on_connect;
    conn->on_recv = on_recv;
    conn->on_close = on_close;

    int r = uv_read_start((uv_stream_t *)cli, alloc_buffer, on_uv_read);
    IF_UV_ERROR(r, "tcp start read error", {
        free_conn(conn);
        return NULL;
    });

    return conn;
}

// void free_tcp_connection(tcp_connection_t *conn) {
//     if (!conn) {
//         return;
//     }
//     _FREE_IF(conn);
// }

bool tcp_send(tcp_connection_t *conn, const char *buf, ssize_t size) {
    _LOG("tcp send %zd", size);
    if (!conn || !buf || size <= 0) {
        return false;
    }

    write_req_t *req = (write_req_t *)malloc(sizeof(write_req_t));
    char *wbuf = (char *)_CALLOC(1, size);
    memcpy(wbuf, buf, size);
    req->buf = uv_buf_init((char *)wbuf, size);
    // req->buf = uv_buf_init((char *)buf, size);

    int r = uv_write((uv_write_t *)req, (uv_stream_t *)conn->cli, &req->buf, 1, on_uv_write);
    IF_UV_ERROR(r, "tcp send error", {
        free_write_req((uv_write_t *)req);
        return false;
    });
    return true;
}

void close_tcp_connection(tcp_connection_t *conn) {
    if (!conn) {
        return;
    }
    if (!conn->cli) {
        free_conn(conn);
    }
    uv_close((uv_handle_t *)conn->cli, on_uv_close);
}

bool tcp_connect(uv_loop_t *loop, const char *ip, uint16_t port, void *data, on_tcp_connect_t on_connect,
                 on_tcp_recv_t on_recv, on_tcp_close_t on_close) {
    if (!loop || !ip || port <= 0) {
        return false;
    }

    struct sockaddr_in addr;
    int r = uv_ip4_addr(ip, port, &addr);
    IF_UV_ERROR(r, "tcp connect error", { return false; });

    uv_tcp_t *cli = (uv_tcp_t *)_CALLOC(1, sizeof(uv_tcp_t));
    _CHECK_OOM(cli);
    r = uv_tcp_init(loop, cli);
    IF_UV_ERROR(r, "tcp connect error", {
        uv_close((uv_handle_t *)cli, on_uv_close);
        return false;
    });

    connect_req_t *connect_req = (connect_req_t *)_CALLOC(1, sizeof(connect_req_t));
    connect_req->data = data;
    // connect_req->on_accept = NULL;
    connect_req->on_close = on_close;
    connect_req->on_connect = on_connect;
    connect_req->on_recv = on_recv;
    // cli->data = connect_req;
    r = uv_tcp_connect((uv_connect_t *)connect_req, cli, (const struct sockaddr *)&addr, on_uv_connect);
    IF_UV_ERROR(r, "tcp connect error", {
        _FREE_IF(connect_req);
        uv_close((uv_handle_t *)cli, on_uv_close);
        return false;
    });

    return true;
}

/* -------------------------------------------------------------------------- */
/*                                    test                                    */
/* -------------------------------------------------------------------------- */
// void on_tcp_accept(tcp_connection_t *conn) {

//     // TODO:
// }

// void on_tcp_connect(tcp_connection_t *conn) {
//     _LOG("connect ok");
//     // TODO:
// }

// void on_tcp_recv(tcp_connection_t *conn, const char *buf, ssize_t size) {
//     // _LOG("recv:%s", buf);
//     bool rt = tcp_send(conn, buf, size);
//     assert(rt);
//     // TODO:
// }

// void on_tcp_close(tcp_connection_t *conn) {
//     _LOG("close %d", conn->id);
//     // TODO:
// }

// int main(int argc, char const *argv[]) {
//     uv_loop_t *loop = uv_default_loop();
//     bool rt = tcp_connect(loop, "127.0.0.1", 6666, NULL, on_tcp_connect, on_tcp_recv, on_tcp_close);
//     assert(rt);
//     int r = uv_run(loop, UV_RUN_DEFAULT);
//     _LOG("exit %d", r);
//     return r;
// }
