#include "tcp_client.h"

#include "utils.h"

static void on_uv_connect(uv_connect_t *req, int status) {
    tcp_connection_t *conn = (tcp_connection_t *)req->data;

    IF_UV_ERROR(status, "tcp client connect error", {
        close_tcp_connection(conn);
        _FREE_IF(req);
        return;
    });

    if (conn->on_connect) {
        conn->on_connect(conn);
    }

    // uv_stream_t *stream = req->handle;

    // /* close the socket, the hard way */
    // close_socket((uv_tcp_t *)stream);

    // buf = uv_buf_init("hello\n", 6);
    // r = uv_write(&write_req, stream, &buf, 1, write_cb);
    // ASSERT_OK(r);
}

tcp_connection_t *tcp_connect(uv_loop_t *loop, const char *ip, uint16_t port, void *data, on_tcp_accept_t on_accept,
                              on_tcp_connect_t on_connect, on_tcp_recv_t on_recv, on_tcp_close_t on_close) {
    if (!loop || !ip || port <= 0) {
        return NULL;
    }

    struct sockaddr_in addr;
    int r = uv_ip4_addr(ip, port, &addr);
    IF_UV_ERROR(r, "tcp connect error", { return NULL; });

    uv_tcp_t *cli = (uv_tcp_t *)_CALLOC(1, sizeof(uv_tcp_t));
    _CHECK_OOM(cli);
    r = uv_tcp_init(loop, cli);
    IF_UV_ERROR(r, "tcp connect error", {
        _FREE_IF(cli);
        return NULL;
    });

    tcp_connection_t *conn =
        init_tcp_connection(cli->accepted_fd, cli, NULL, cli, data, on_accept, on_connect, on_recv, on_close);
    if (!conn) {
        _FREE_IF(cli);
        return NULL;
    }

    uv_connect_t *connect_req = (uv_connect_t *)_CALLOC(1, sizeof(uv_connect_t));
    connect_req->data = conn;
    r = uv_tcp_connect(connect_req, cli, (const struct sockaddr *)&addr, on_uv_connect);
    IF_UV_ERROR(r, "tcp connect error", {
        _FREE_IF(cli);
        _FREE_IF(connect_req);
        _FREE_IF(conn);
        return NULL;
    });

    return conn;
}
