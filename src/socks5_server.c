#include "socks5_server.h"

#include "utils.h"

// #define DEF_SOCKS5_IP 127.0.0.1
// #define DEF_SOCKS5_PORT 6666
#define DEF_BACKLOG 128

/* -------------------------------------------------------------------------- */
/*                          socks5 connection manager                         */
/* -------------------------------------------------------------------------- */
static socks5_connection_t *get_conn(socks5_server_t *socks5, int id) {
    socks5_connection_t *conn = NULL;
    HASH_FIND_INT(socks5->conns, &id, conn);
    return conn;
}

static socks5_connection_t *init_conn(socks5_server_t *socks5, uv_tcp_t *cli, void *data) {
    socks5_connection_t *conn = (socks5_connection_t *)_CALLOC(1, sizeof(socks5_connection_t));
    conn->socks5 = socks5;
    conn->id = cli->accepted_fd;
    conn->data = data;
    HASH_ADD_INT(socks5->conns, id, conn);
    return conn;
}

static void free_conn(socks5_connection_t *conn) {
    if (!conn) {
        return;
    }
    if (conn->socks5 && conn->socks5->conns) {
        HASH_DEL(conn->socks5->conns, conn);
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
    socks5_connection_t *conn = (socks5_connection_t *)handle->data;
    if (!conn) {
        goto on_uv_close_end;
    }

    if (conn->socks5->on_close) {
        conn->socks5->on_close(conn->socks5, conn->id);
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
        socks5_connection_t *conn = (socks5_connection_t *)cli->data;
        if (conn && conn->socks5->on_recv) {
            // TODO: parse socks5 protocol
            conn->socks5->on_recv(conn->socks5, conn->id, buf->base, nread);
        }
        _LOG("%s", buf->base);

        // // echo
        // write_req_t *req = (write_req_t *)malloc(sizeof(write_req_t));
        // req->buf = uv_buf_init(buf->base, nread);
        // uv_write((uv_write_t *)req, cli, &req->buf, 1, on_uv_write);

        return;
    }
    if (nread < 0) {
        if (nread != UV_EOF) fprintf(stderr, "socks5 read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t *)cli, on_uv_close);
    }

    free(buf->base);
}

static void on_uv_accept(uv_stream_t *server, int status) {
    _LOG("on_uv_accept");
    IF_UV_ERROR(status, "new socks5 connection error", { return; });

    uv_tcp_t *cli = (uv_tcp_t *)_CALLOC(1, sizeof(uv_tcp_t));
    int r = uv_tcp_init(server->loop, cli);
    IF_UV_ERROR(r, "new socks5 connection error", {
        _FREE_IF(cli);
        return;
    });

    socks5_server_t *socks5 = (socks5_server_t *)server->data;

    r = uv_accept(server, (uv_stream_t *)cli);
    IF_UV_ERROR(r, "new socks5 connection error", { uv_close((uv_handle_t *)cli, on_uv_close); });

    socks5_connection_t *conn = init_conn(socks5, cli, NULL);
    if (socks5->on_accept) {
        socks5->on_accept(socks5, conn->id);
    }
    cli->data = conn;

    uv_read_start((uv_stream_t *)cli, alloc_buffer, on_uv_read);
}

void on_uv_shutdown(uv_shutdown_t *req, int status) {
    socks5_server_t *socks5 = (socks5_server_t *)req->data;
    if (socks5->conns) {
        socks5_connection_t *conn, *tmp;
        HASH_ITER(hh, socks5->conns, conn, tmp) {
            // free_conn(conn);
            uv_close((uv_handle_t *)conn->client, on_uv_close);
        }
    }
    _FREE_IF(req);
    _FREE_IF(socks5);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

socks5_server_t *init_socks5_server(uv_loop_t *loop, const char *ip, uint16_t port, on_socks5_accept_t on_accept,
                                    on_socks5_recv_t on_recv, on_socks5_close_t on_close) {
    if (!loop || !ip || port <= 0) {
        return NULL;
    }

    uv_tcp_t *tcp = _CALLOC(1, sizeof(uv_tcp_t));
    _CHECK_OOM(tcp);
    int r = uv_tcp_init(loop, tcp);
    IF_UV_ERROR(r, "init socks5 server error", {
        _FREE_IF(tcp);
        return NULL;
    });
    struct sockaddr_in sockaddr;
    r = uv_ip4_addr(ip, port, &sockaddr);
    IF_UV_ERROR(r, "init socks5 server error", {
        _FREE_IF(tcp);
        return NULL;
    });

    uv_tcp_bind(tcp, (const struct sockaddr *)&sockaddr, 0);
    r = uv_listen((uv_stream_t *)tcp, DEF_BACKLOG, on_uv_accept);
    IF_UV_ERROR(r, "init socks5 server error", {
        _FREE_IF(tcp);
        return NULL;
    });

    socks5_server_t *socks5 = (socks5_server_t *)_CALLOC(1, sizeof(socks5_server_t));
    _CHECK_OOM(socks5);
    socks5->conns = NULL;
    socks5->ip = (char *)ip;
    socks5->port = port;
    socks5->loop = loop;
    socks5->on_accept = on_accept;
    socks5->on_close = on_close;
    socks5->on_recv = on_recv;
    socks5->tcp = tcp;

    tcp->data = socks5;
    return socks5;
}

void free_socks5_server(socks5_server_t *socks5) {
    if (!socks5) {
        return;
    }

    int r = -1;
    if (socks5->tcp) {
        r = uv_read_stop((uv_stream_t *)socks5->tcp);
        IF_UV_ERROR(r, "tcp server stop read error", {});
        uv_shutdown_t *req = (uv_shutdown_t *)_CALLOC(1, sizeof(uv_shutdown));
        req->data = socks5;
        r = uv_shutdown(req, (uv_stream_t *)socks5->tcp, on_uv_shutdown);
        IF_UV_ERROR(r, "tcp server shutdown error", {});
    }

    if (r <= 0) {
        fprintf(stderr, "force shutdown tcp server\n");
        if (socks5->conns) {
            socks5_connection_t *conn, *tmp;
            HASH_ITER(hh, socks5->conns, conn, tmp) { free_conn(conn); }
        }
        _FREE_IF(socks5);
    }

    // if (socks5->conns) {
    //     socks5_connection_t *conn, *tmp;
    //     HASH_ITER(hh, socks5->conns, conn, tmp) { free_conn(conn); }
    // }

    // TODO: safe uv_shutdown
}

bool socks5_server_send(socks5_server_t *socks5, int conn_id, const char *buf, ssize_t size) {
    if (!socks5 || !buf || size <= 0) {
        return false;
    }

    socks5_connection_t *conn = get_conn(socks5, conn_id);
    if (!conn) {
        fprintf(stderr, "socks5 connection does not exsit\n");
        return false;
    }

    write_req_t *req = (write_req_t *)malloc(sizeof(write_req_t));
    req->buf = uv_buf_init((char *)buf, size);

    int r = uv_write((uv_write_t *)req, (uv_stream_t *)conn->client, &req->buf, 1, on_uv_write);
    IF_UV_ERROR(r, "socks5 server send error", {
        _FREE_IF(req);
        return false;
    });
    return true;
}

socks5_connection_t *socks5_server_get_conn(socks5_server_t *socks5, int conn_id) {
    if (!socks5) {
        return NULL;
    }
    return get_conn(socks5, conn_id);
}

/* -------------------------------------------------------------------------- */
/*                                    test                                    */
/* -------------------------------------------------------------------------- */
int main(int argc, char const *argv[]) {
    uv_loop_t *loop = uv_default_loop();
    socks5_server_t *socks5 = init_socks5_server(loop, "127.0.0.1", 6666, NULL, NULL, NULL);
    assert(socks5);
    return uv_run(loop, UV_RUN_DEFAULT);
}
