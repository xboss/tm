#include "tcp_server.h"

#include <stdbool.h>

#include "utils.h"

// #define DEF_SOCKS5_IP 127.0.0.1
// #define DEF_SOCKS5_PORT 6666
#define DEF_BACKLOG 128

/* -------------------------------------------------------------------------- */
/*                        tcp server connection manager                       */
/* -------------------------------------------------------------------------- */
static bool is_conn_exsit(tcp_server_t *serv, tcp_connection_t *conn) {
    if (!conn || !serv || !serv->conns) {
        return false;
    }
    tcp_connection_t *c = NULL;
    HASH_FIND_INT(serv->conns, &conn->id, c);
    return c ? true : false;
}

static bool add_conn(tcp_server_t *serv, tcp_connection_t *conn) {
    if (!conn || !serv || !serv->conns) {
        return false;
    }
    HASH_ADD_INT(serv->conns, id, conn);
    return true;
}

static bool del_conn(tcp_server_t *serv, tcp_connection_t *conn) {
    if (!conn || !serv || !serv->conns) {
        return false;
    }
    HASH_DEL(serv->conns, conn);
    return true;
}

/* -------------------------------------------------------------------------- */
/*                                   server                                   */
/* -------------------------------------------------------------------------- */

static void on_tcp_recv(tcp_connection_t *conn, const char *buf, ssize_t size) {
    // _LOG("recv:%s", buf);
    if (conn->serv->on_recv) {
        conn->serv->on_recv(conn, buf, size);
    }
    // bool rt = tcp_send(conn, buf, size);
    // assert(rt);

    // TODO:
}

static void on_tcp_close(tcp_connection_t *conn) {
    _LOG("server close %d", conn->id);
    del_conn(conn->serv, conn);
    if (conn->serv->on_close) {
        conn->serv->on_close(conn);
    }

    // TODO:
}

static void on_uv_accept(uv_stream_t *server, int status) {
    _LOG("on_uv_accept");
    IF_UV_ERROR(status, "new tcp server connection error", { return; });
    uv_tcp_t *cli = (uv_tcp_t *)_CALLOC(1, sizeof(uv_tcp_t));
    _CHECK_OOM(cli);
    int r = uv_tcp_init(server->loop, cli);
    IF_UV_ERROR(r, "new tcp server connection error", {
        _FREE_IF(cli);
        return;
    });
    tcp_server_t *serv = (tcp_server_t *)server->data;
    r = uv_accept(server, (uv_stream_t *)cli);
    IF_UV_ERROR(r, "new tcp server connection error", { _FREE_IF(cli); });
    tcp_connection_t *conn = init_tcp_connection(serv->cid++, cli, serv, serv->data, NULL, on_tcp_recv, on_tcp_close);
    if (conn) {
        add_conn(serv, conn);
    }
    if (serv->on_accept) {
        serv->on_accept(conn);
    }
}

static void on_uv_shutdown(uv_shutdown_t *req, int status) {
    tcp_server_t *serv = (tcp_server_t *)req->data;
    if (serv->conns) {
        tcp_connection_t *conn, *tmp;
        HASH_ITER(hh, serv->conns, conn, tmp) { close_tcp_connection(conn); }
    }
    _FREE_IF(req);
    _FREE_IF(serv);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

tcp_server_t *init_tcp_server(uv_loop_t *loop, const char *ip, uint16_t port, void *data, on_tcp_accept_t on_accept,
                              on_tcp_recv_t on_recv, on_tcp_close_t on_close) {
    if (!loop || !ip || port <= 0) {
        return NULL;
    }

    uv_tcp_t *tcp = (uv_tcp_t *)_CALLOC(1, sizeof(uv_tcp_t));
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

    tcp_server_t *serv = (tcp_server_t *)_CALLOC(1, sizeof(tcp_server_t));
    _CHECK_OOM(serv);
    serv->cid = 1;
    serv->conns = NULL;
    serv->ip = (char *)ip;
    serv->port = port;
    serv->loop = loop;
    serv->on_accept = on_accept;
    serv->on_close = on_close;
    serv->on_recv = on_recv;
    serv->tcp = tcp;
    serv->data = data;

    tcp->data = serv;
    return serv;
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
    } else {
        // TODO: release conns
        _FREE_IF(tcp_serv);
    }

    if (r < 0 && tcp_serv) {
        // TODO:  force shutdown
        fprintf(stderr, "force shutdown tcp server\n");
        if (tcp_serv->conns) {
            tcp_connection_t *conn, *tmp;
            HASH_ITER(hh, tcp_serv->conns, conn, tmp) {
                close_tcp_connection(conn);
                // free_conn(conn);
            }
        }
        _FREE_IF(tcp_serv);
    }
}

/* -------------------------------------------------------------------------- */
/*                                    test                                    */
/* -------------------------------------------------------------------------- */
// int main(int argc, char const *argv[]) {
//     uv_loop_t *loop = uv_default_loop();
//     tcp_server_t *tcp_serv = init_tcp_server(loop, "127.0.0.1", 6666, NULL, NULL, NULL);
//     assert(tcp_serv);
//     return uv_run(loop, UV_RUN_DEFAULT);
// }
