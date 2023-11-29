#include "socks5_server.h"

#include "utils.h"

/* -------------------------------------------------------------------------- */
/*                                   server                                   */
/* -------------------------------------------------------------------------- */
#define SS5_VER 0x05U
#define SS5_CMD_CONNECT 0x01U
#define SS5_CMD_BIND 0x02U
#define SS5_CMD_UDP_ASSOCIATE 0x03U

#define SS5_ATYP_IPV4 0x01U
#define SS5_ATYP_DOMAIN 0x03U
#define SS5_ATYP_IPV6 0x04U

/*
REP: 回复请求的状态
0x00 成功代理
0x01 SOCKS服务器出现了错误
0x02 不允许的连接
0x03 找不到网络
0x04 找不到主机
0x05 连接被拒
0x06 TTL超时
0x07 不支持的CMD
0x08 不支持的ATYP
 */
#define SS5_REP_OK 0x00U
#define SS5_REP_ERR 0x01U
#define SS5_REP_HOST_ERR 0x04U

#define SS5_PHASE_AUTH 1
#define SS5_PHASE_REQ 2
#define SS5_PHASE_DATA 3
#define SS5_PHASE_AUTH_NP 4

struct socks5_server_s {
    uv_loop_t *loop;
    tcp_server_t *tcp_serv;
    // on_socks5_accept_t on_accept;
    // on_socks5_recv_t on_recv;
    // on_socks5_close_t on_close;
};

bool resolve_domain(uv_loop_t *loop, socks5_connection_t *ss5_conn, char *domain, int family);

static void free_ss5_conn(socks5_connection_t *conn) {
    if (!conn) {
        return;
    }
    conn->phase = -9999;  // TODO: test
    if (conn->resolver) {
        conn->resolver->data = NULL;
    }
    if (conn->raw) {
        _FREE_IF(conn->raw);
    }
    _FREE_IF(conn);
}

static void ss5_auth(const u_char *buf, ssize_t size, socks5_connection_t *ss5_conn) {
    if (*buf != SS5_VER || size < 3) {
        goto ss5_auth_error;
    }
    u_char nmethods = buf[1];

    char ok[2] = {SS5_VER, 0x00};
    for (u_char i = 0; i < nmethods; i++) {
        if (buf[2 + i] == 0x00) {
            tcp_send(ss5_conn->fr_conn, ok, 2);
            ss5_conn->phase = SS5_PHASE_REQ;
        } else if (buf[2 + i] == 0x02) {
            tcp_send(ss5_conn->fr_conn, ok, 2);
            ss5_conn->phase = SS5_PHASE_AUTH_NP;
        }
    }
    return;

ss5_auth_error:
    fprintf(stderr, "socks5 auth error\n");
}

static void ss5_auth_np(const u_char *buf, ssize_t size, socks5_connection_t *ss5_conn) {
    if (*buf != SS5_VER || size < 5) {
        goto ss5_auth_name_pwd_error;
    }
    char ok[2] = {SS5_VER, 0x00};
    tcp_send(ss5_conn->fr_conn, ok, 2);
    ss5_conn->phase = SS5_PHASE_REQ;
    return;

ss5_auth_name_pwd_error:
    fprintf(stderr, "socks5 auth name password error\n");
}

// static bool send_ss5_req_ack(socks5_connection_t *ss5_conn, u_char rep) {
//     u_char *raw = (u_char *)_CALLOC(1, 6 + ss5_conn->addr_raw_len);
//     int idx = 0;
//     raw[idx++] = SS5_VER;
//     raw[idx++] = 0x00U;
//     raw[idx++] = rep;
//     raw[idx++] = ss5_conn->atyp;
//     int ri = 0;
//     for (idx; idx < ss5_conn->addr_raw_len + 4; idx++) {
//         raw[idx] = ss5_conn->addr_raw[ri++];
//     }
//     raw[idx++] = ss5_conn->port_raw[0];
//     raw[idx++] = ss5_conn->port_raw[1];

//     // tcp_send(ss5_conn->tcp_conn, err, sizeof(err));
// }

static bool ss5_req_ack(socks5_connection_t *ss5_conn, u_char type) {
    u_char *ack_raw = (u_char *)_CALLOC(1, ss5_conn->raw_len);
    _CHECK_OOM(ack_raw);
    memcpy(ack_raw, ss5_conn->raw, ss5_conn->raw_len);
    ack_raw[1] = type;
    bool rt = tcp_send(ss5_conn->fr_conn, (const char *)ack_raw, ss5_conn->raw_len);
    _FREE_IF(ack_raw);
    return rt;
}

static void on_back_connect(tcp_connection_t *conn) {
    _LOG("back connect ok");
    socks5_connection_t *ss5_conn = (socks5_connection_t *)conn->data;
    assert(ss5_conn);
    ss5_conn->bk_conn = conn;

    // u_char *ack_raw = (u_char *)_CALLOC(1, ss5_conn->raw_len);
    // memcpy(ack_raw, ss5_conn->raw, ss5_conn->raw_len);
    // ack_raw[1] = SS5_REP_OK;
    // bool rt = tcp_send(ss5_conn->fr_conn, (const char *)ack_raw, ss5_conn->raw_len);
    // _FREE_IF(ack_raw);
    // assert(rt);

    if (ss5_req_ack(ss5_conn, SS5_REP_OK)) {
        ss5_conn->phase = SS5_PHASE_DATA;
    }
}

static void on_back_recv(tcp_connection_t *conn, const char *buf, ssize_t size) {
    // _LOG("recv:%s", buf);
    socks5_connection_t *ss5_conn = (socks5_connection_t *)conn->data;
    assert(ss5_conn);
    bool rt = tcp_send(ss5_conn->fr_conn, buf, size);
    assert(rt);
}

static void on_back_close(tcp_connection_t *conn) {
    _LOG("back close %d", conn->id);
    socks5_connection_t *ss5_conn = (socks5_connection_t *)conn->data;
    assert(ss5_conn);
    // stop repeating callback
    conn->on_close = NULL;
    if (ss5_conn->fr_conn) {
        ss5_conn->fr_conn->on_close = NULL;
        // close fr_conn
        close_tcp_connection(ss5_conn->fr_conn);
    }
    free_ss5_conn(ss5_conn);
}

static void ss5_req(const u_char *buf, ssize_t size, socks5_connection_t *ss5_conn) {
    if (*buf != SS5_VER || size < 7) {
        goto ss5_auth_req_error;
    }

    u_char cmd = buf[1];
    if (cmd == SS5_CMD_BIND || cmd == SS5_CMD_UDP_ASSOCIATE) {
        // TODO: support bind and udp associate
        _LOG("now only 'connect' command is supported.");
        goto ss5_auth_req_error;
    }
    if (cmd != SS5_CMD_CONNECT) {
        goto ss5_auth_req_error;
    }

    socks5_server_t *socks5 = (socks5_server_t *)ss5_conn->fr_conn->serv->data;
    u_char atyp = buf[3];
    // ss5_conn->atyp = atyp;
    // u_char dst_addr[128] = {0};
    if (atyp == SS5_ATYP_IPV4) {
        // u_char dst_addr[4] = {0};
        ss5_conn->port = ntohs(*(uint16_t *)(buf + 8));

        ss5_conn->raw_len = size;
        ss5_conn->raw = (u_char *)_CALLOC(1, size);
        _CHECK_OOM(ss5_conn->raw);
        memcpy(ss5_conn->raw, buf, size);

        // memcpy(ss5_conn->port_raw, buf[7], 2);
        // ss5_conn->addr_raw_len = 4;
        // ss5_conn->addr_raw = (u_char *)_CALLOC(1, ss5_conn->addr_raw_len);
        // memcpy(ss5_conn->addr_raw, buf[4], ss5_conn->addr_raw_len);

        // char ip[17] = {0};
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = *(in_addr_t *)(buf + 4);
        // *(struct sockaddr_in *)buf[4];  // TODO: ntoh?
        uv_ip4_name((const struct sockaddr_in *)&addr, ss5_conn->ip, 16);
        if (!tcp_connect(socks5->loop, ss5_conn->ip, ss5_conn->port, ss5_conn, on_back_connect, on_back_recv,
                         on_back_close)) {
            // error
            ss5_req_ack(ss5_conn, SS5_REP_ERR);
        }
    } else if (atyp == SS5_ATYP_IPV6) {
        _LOG("ss5 ipv6 type");
        // u_char dst_addr[16] = {0};
        uint16_t port = ntohs((uint16_t)buf[19]);
        // TODO: connect to dest
    } else if (atyp == SS5_ATYP_DOMAIN) {
        _LOG("ss5 domain type");

        ss5_conn->raw_len = size;
        ss5_conn->raw = (u_char *)_CALLOC(1, size);
        _CHECK_OOM(ss5_conn->raw);
        memcpy(ss5_conn->raw, buf, size);

        int d_len = (int)buf[4];  // TODO: unsigned to signed overflow?
        char *domain = (char *)_CALLOC(1, d_len + 1);
        _CHECK_OOM(domain);
        memcpy(domain, buf + 5, d_len);

        ss5_conn->port = ntohs(*(uint16_t *)(buf + 4 + d_len + 1));
        _LOG("%s:%u", domain, ss5_conn->port);
        // resolve DNS
        if (!resolve_domain(socks5->loop, ss5_conn, domain, AF_INET)) {
            ss5_req_ack(ss5_conn, SS5_REP_HOST_ERR);
        }
    } else {
        goto ss5_auth_req_error;
    }

    // ss5_conn->phase = SS5_PHASE_DATA;
    return;

ss5_auth_req_error:
    fprintf(stderr, "socks5 request error\n");
}

static void on_front_close(tcp_connection_t *conn) {
    _LOG("on front close");
    socks5_server_t *socks5 = (socks5_server_t *)conn->serv->data;
    socks5_connection_t *ss5_conn = (socks5_connection_t *)conn->data;
    assert(ss5_conn);
    // stop repeating callback
    conn->on_close = NULL;
    if (ss5_conn->bk_conn) {
        ss5_conn->bk_conn->on_close = NULL;
        // close bk_conn
        close_tcp_connection(ss5_conn->bk_conn);
    }
    free_ss5_conn(ss5_conn);
}

static void on_front_recv(tcp_connection_t *conn, const char *buf, ssize_t size) {
    _LOG("on front recv");
    socks5_server_t *socks5 = (socks5_server_t *)conn->serv->data;
    socks5_connection_t *ss5_conn = (socks5_connection_t *)conn->data;
    assert(ss5_conn);
    bool rt = false;
    switch (ss5_conn->phase) {
        case SS5_PHASE_AUTH:
            ss5_auth((const u_char *)buf, size, ss5_conn);
            break;
        case SS5_PHASE_AUTH_NP:
            ss5_auth_np((const u_char *)buf, size, ss5_conn);
            break;
        case SS5_PHASE_REQ:
            ss5_req((const u_char *)buf, size, ss5_conn);
            break;
        case SS5_PHASE_DATA:
            rt = tcp_send(ss5_conn->bk_conn, buf, size);
            assert(rt);
            break;
        default:
            break;
    }
}

static void on_front_accept(tcp_connection_t *conn) {
    _LOG("on front accept");
    // tcp_server_t *tcp_serv = conn->serv
    socks5_server_t *socks5 = (socks5_server_t *)conn->serv->data;
    socks5_connection_t *ss5_conn = (socks5_connection_t *)_CALLOC(1, sizeof(socks5_connection_t));
    _CHECK_OOM(ss5_conn);
    ss5_conn->phase = SS5_PHASE_AUTH;
    ss5_conn->fr_conn = conn;
    conn->data = ss5_conn;
    // socks5->on_accept(ss5_conn);
}

// typedef struct {
//     socks5_connection_t *ss5_conn;
//     socks5_server_t *socks5;
// } addr_info_ex_t;

void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
    _LOG("on_resolved");
    IF_UV_ERROR(status, "on resolve domain error", { return; });

    socks5_connection_t *ss5_conn = (socks5_connection_t *)resolver->data;
    if (!ss5_conn) {
        _FREE_IF(resolver);
        return;
    }

    socks5_server_t *socks5 = (socks5_server_t *)ss5_conn->fr_conn->serv->data;
    assert(socks5);

    if (res->ai_family == AF_INET) {
        // ipv4
        uv_ip4_name((struct sockaddr_in *)res->ai_addr, ss5_conn->ip, 16);
        if (!tcp_connect(socks5->loop, ss5_conn->ip, ss5_conn->port, ss5_conn, on_back_connect, on_back_recv,
                         on_back_close)) {
            // error
            ss5_req_ack(ss5_conn, SS5_REP_ERR);
        }
    } else if (res->ai_family == AF_INET6) {
        // ipv6
        uv_ip4_name((struct sockaddr_in *)res->ai_addr, ss5_conn->ip, 46);
        // TODO:
    } else {
        // ipv4 or ipv6
        uv_ip4_name((struct sockaddr_in *)res->ai_addr, ss5_conn->ip, 46);
        // TODO:
    }
    _LOG("resolve: %s:%u", ss5_conn->ip, ss5_conn->port);

    ss5_conn->resolver = NULL;
    _FREE_IF(resolver);
}

bool resolve_domain(uv_loop_t *loop, socks5_connection_t *ss5_conn, char *domain, int family) {
    _LOG("resolve_domain %d", ss5_conn->fr_conn->id);
    struct addrinfo hints;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

    uv_getaddrinfo_t *resolver = (uv_getaddrinfo_t *)_CALLOC(1, sizeof(uv_getaddrinfo_t));
    ss5_conn->resolver = resolver;
    resolver->data = ss5_conn;
    assert(ss5_conn->port);
    int r = uv_getaddrinfo(loop, resolver, on_resolved, domain, NULL, &hints);
    IF_UV_ERROR(r, "resolve domain error", { return false; });

    return true;
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

socks5_server_t *init_socks5_server(uv_loop_t *loop, const char *ip, uint16_t port) {
    if (!loop || !ip || port <= 0) {
        return NULL;
    }

    tcp_server_t *tcp_serv = init_tcp_server(loop, ip, port, NULL, on_front_accept, on_front_recv, on_front_close);
    if (!tcp_serv) {
        return NULL;
    }

    socks5_server_t *socks5 = (socks5_server_t *)_CALLOC(1, sizeof(socks5_server_t));
    _CHECK_OOM(socks5);
    tcp_serv->data = socks5;
    socks5->loop = loop;
    socks5->tcp_serv = tcp_serv;
    // socks5->on_accept = on_accept;
    // socks5->on_close = on_close;
    // socks5->on_recv = on_recv;

    return socks5;
}

void free_socks5_server(socks5_server_t *socks5) {
    if (!socks5) {
        return;
    }

    if (socks5->tcp_serv) {
        free_tcp_server(socks5->tcp_serv);
    }

    free(socks5);
}

/* -------------------------------------------------------------------------- */
/*                                    test                                    */
/* -------------------------------------------------------------------------- */

// int main(int argc, char const *argv[]) {
//     uv_loop_t *loop = uv_default_loop();
//     socks5_server_t *socks5 = init_socks5_server(loop, "127.0.0.1", 6666, NULL, NULL, NULL);
//     assert(socks5);
//     return uv_run(loop, UV_RUN_DEFAULT);
// }
