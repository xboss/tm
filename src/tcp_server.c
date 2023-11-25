#include "tcp_server.h"

#include "utils.h"

// #define DEF_SOCKS5_IP 127.0.0.1
// #define DEF_SOCKS5_PORT 6666
#define DEF_BACKLOG 128

/* -------------------------------------------------------------------------- */
/*                        tcp server connection manager                       */
/* -------------------------------------------------------------------------- */
static tcp_connection_t *get_conn(tcp_server_t *tcp_serv, int id) {
    tcp_connection_t *conn = NULL;
    HASH_FIND_INT(tcp_serv->conns, &id, conn);
    return conn;
}

static tcp_connection_t *init_conn(tcp_server_t *tcp_serv, uv_tcp_t *cli, void *data) {
    tcp_connection_t *conn = (tcp_connection_t *)_CALLOC(1, sizeof(tcp_connection_t));
    conn->tcp_serv = tcp_serv;
    conn->id = cli->accepted_fd;
    conn->data = data;
    HASH_ADD_INT(tcp_serv->conns, id, conn);
    return conn;
}

static void free_conn(tcp_connection_t *conn) {
    if (!conn) {
        return;
    }
    if (conn->tcp_serv && conn->tcp_serv->conns) {
        HASH_DEL(conn->tcp_serv->conns, conn);
    }
    _FREE_IF(conn);
}

/* -------------------------------------------------------------------------- */
/*                                   server                                   */
/* -------------------------------------------------------------------------- */

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

void free_write_req(uv_write_t *req) {
    write_req_t *wr = (write_req_t *)req;
    free(wr->buf.base);
    free(wr);
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *)_CALLOC(1, suggested_size);
    buf->len = suggested_size;
}

static void on_uv_close(uv_handle_t *handle) {
    _LOG("on_uv_close");
    tcp_connection_t *conn = (tcp_connection_t *)handle->data;
    if (!conn) {
        goto on_uv_close_end;
    }

    if (conn->tcp_serv->on_close) {
        conn->tcp_serv->on_close(conn->tcp_serv, conn->id);
        free_conn(conn);
    }

on_uv_close_end:
    _FREE_IF(handle);
}

void on_uv_write(uv_write_t *req, int status) {
    _LOG("on_uv_write");
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    free_write_req(req);
}

static void on_uv_read(uv_stream_t *cli, ssize_t nread, const uv_buf_t *buf) {
    _LOG("on_uv_read");
    if (nread > 0) {
        tcp_connection_t *conn = (tcp_connection_t *)cli->data;
        if (conn && conn->tcp_serv->on_recv) {
            conn->tcp_serv->on_recv(conn->tcp_serv, conn->id, buf->base, nread);
        }
        _LOG("%s", buf->base);

        // // echo
        // write_req_t *req = (write_req_t *)malloc(sizeof(write_req_t));
        // req->buf = uv_buf_init(buf->base, nread);
        // uv_write((uv_write_t *)req, cli, &req->buf, 1, on_uv_write);

        return;
    }
    if (nread < 0) {
        if (nread != UV_EOF) fprintf(stderr, "tcp server read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t *)cli, on_uv_close);
    }

    free(buf->base);
}

static void on_uv_accept(uv_stream_t *server, int status) {
    _LOG("on_uv_accept");
    IF_UV_ERROR(status, "new tcp server connection error", { return; });

    uv_tcp_t *cli = (uv_tcp_t *)_CALLOC(1, sizeof(uv_tcp_t));
    int r = uv_tcp_init(server->loop, cli);
    IF_UV_ERROR(r, "new tcp server connection error", {
        _FREE_IF(cli);
        return;
    });

    tcp_server_t *tcp_serv = (tcp_server_t *)server->data;

    r = uv_accept(server, (uv_stream_t *)cli);
    IF_UV_ERROR(r, "new tcp server connection error", { uv_close((uv_handle_t *)cli, on_uv_close); });

    tcp_connection_t *conn = init_conn(tcp_serv, cli, NULL);
    if (tcp_serv->on_accept) {
        tcp_serv->on_accept(tcp_serv, conn->id);
    }
    cli->data = conn;

    uv_read_start((uv_stream_t *)cli, alloc_buffer, on_uv_read);
}

void on_uv_shutdown(uv_shutdown_t *req, int status) {
    tcp_server_t *tcp_serv = (tcp_server_t *)req->data;
    if (tcp_serv->conns) {
        tcp_connection_t *conn, *tmp;
        HASH_ITER(hh, tcp_serv->conns, conn, tmp) {
            // free_conn(conn);
            uv_close((uv_handle_t *)conn->client, on_uv_close);
        }
    }
    _FREE_IF(req);
    _FREE_IF(tcp_serv);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

tcp_server_t *init_tcp_server(uv_loop_t *loop, const char *ip, uint16_t port, on_tcp_accept_t on_accept,
                              on_tcp_recv_t on_recv, on_tcp_close_t on_close) {
    if (!loop || !ip || port <= 0) {
        return NULL;
    }

    uv_tcp_t *tcp = _CALLOC(1, sizeof(uv_tcp_t));
    _CHECK_OOM(tcp);
    int r = uv_tcp_init(loop, tcp);
    IF_UV_ERROR(r, "init tcp server error", {
        _FREE_IF(tcp);
        return NULL;
    });
    struct sockaddr_in sockaddr;
    r = uv_ip4_addr(ip, port, &sockaddr);
    IF_UV_ERROR(r, "init tcp server error", {
        _FREE_IF(tcp);
        return NULL;
    });

    uv_tcp_bind(tcp, (const struct sockaddr *)&sockaddr, 0);
    r = uv_listen((uv_stream_t *)tcp, DEF_BACKLOG, on_uv_accept);
    IF_UV_ERROR(r, "init tcp server error", {
        _FREE_IF(tcp);
        return NULL;
    });

    tcp_server_t *tcp_serv = (tcp_server_t *)_CALLOC(1, sizeof(tcp_server_t));
    _CHECK_OOM(tcp_serv);
    tcp_serv->conns = NULL;
    tcp_serv->ip = (char *)ip;
    tcp_serv->port = port;
    tcp_serv->loop = loop;
    tcp_serv->on_accept = on_accept;
    tcp_serv->on_close = on_close;
    tcp_serv->on_recv = on_recv;
    tcp_serv->tcp = tcp;

    tcp->data = tcp_serv;
    return tcp_serv;
}

void free_tcp_server(tcp_server_t *tcp_serv) {
    if (!tcp_serv) {
        return;
    }

    int r = -1;
    if (tcp_serv->tcp) {
        r = uv_read_stop((uv_stream_t *)tcp_serv->tcp);
        IF_UV_ERROR(r, "tcp server stop read error", {});
        uv_shutdown_t *req = (uv_shutdown_t *)_CALLOC(1, sizeof(uv_shutdown));
        req->data = tcp_serv;
        r = uv_shutdown(req, (uv_stream_t *)tcp_serv->tcp, on_uv_shutdown);
        IF_UV_ERROR(r, "tcp server shutdown error", {});
    }

    if (r <= 0) {
        fprintf(stderr, "force shutdown tcp server\n");
        if (tcp_serv->conns) {
            tcp_connection_t *conn, *tmp;
            HASH_ITER(hh, tcp_serv->conns, conn, tmp) { free_conn(conn); }
        }
        _FREE_IF(tcp_serv);
    }

    // if (tcp_serv->conns) {
    //     tcp_connection_t *conn, *tmp;
    //     HASH_ITER(hh, tcp_serv->conns, conn, tmp) { free_conn(conn); }
    // }

    // TODO: safe uv_shutdown
}

bool tcp_server_send(tcp_server_t *tcp_serv, int conn_id, const char *buf, ssize_t size) {
    if (!tcp_serv || !buf || size <= 0) {
        return false;
    }

    tcp_connection_t *conn = get_conn(tcp_serv, conn_id);
    if (!conn) {
        fprintf(stderr, "tcp server connection does not exsit\n");
        return false;
    }

    write_req_t *req = (write_req_t *)malloc(sizeof(write_req_t));
    req->buf = uv_buf_init((char *)buf, size);

    int r = uv_write((uv_write_t *)req, (uv_stream_t *)conn->client, &req->buf, 1, on_uv_write);
    IF_UV_ERROR(r, "tcp server server send error", {
        _FREE_IF(req);
        return false;
    });
    return true;
}

tcp_connection_t *tcp_server_get_conn(tcp_server_t *tcp_serv, int conn_id) {
    if (!tcp_serv) {
        return NULL;
    }
    return get_conn(tcp_serv, conn_id);
}

/* -------------------------------------------------------------------------- */
/*                                    test                                    */
/* -------------------------------------------------------------------------- */
int main(int argc, char const *argv[]) {
    uv_loop_t *loop = uv_default_loop();
    tcp_server_t *tcp_serv = init_tcp_server(loop, "127.0.0.1", 6666, NULL, NULL, NULL);
    assert(tcp_serv);
    return uv_run(loop, UV_RUN_DEFAULT);
}
