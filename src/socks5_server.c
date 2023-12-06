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
    tcp_t *tcp;
    char *key;
    char *iv;
};

typedef struct {
    uv_getaddrinfo_t resolver;
    tcp_t *tcp;
    int conn_id;
} resolver_req_t;

static void free_ss5_conn(socks5_connection_t *conn) {
    _LOG("free_ss5_conn");
    assert(conn);
    assert(!conn->fr_conn && !conn->bk_conn);
    // if (!conn) {
    //     return;
    // }
    conn->phase = -9999;  // TODO: test
    if (conn->raw) {
        _FREE_IF(conn->raw);
    }
    _FREE_IF(conn);
}

static void close_ss5_conn(tcp_t *tcp, int conn_id) {
    IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    socks5_connection_t *ss5_conn = (socks5_connection_t *)tcp_conn->data;
    if (!ss5_conn) {
        _LOG("ss5_conn does not exist");
        return;
    }
    if (ss5_conn->fr_conn) {
        close_tcp_connection(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id);
        // ss5_conn->fr_conn->data = NULL;
        // ss5_conn->fr_conn = NULL;
    }
    if (ss5_conn->bk_conn) {
        close_tcp_connection(ss5_conn->socks5->tcp, ss5_conn->bk_conn->id);
        // ss5_conn->bk_conn->data = NULL;
        // ss5_conn->bk_conn = NULL;
    }
}

static bool ss5_req_ack(socks5_connection_t *ss5_conn, u_char type) {
    assert(ss5_conn);
    if (!ss5_conn->fr_conn) {
        return false;
    }
    u_char *ack_raw = (u_char *)_CALLOC(1, ss5_conn->raw_len);
    _CHECK_OOM(ack_raw);
    memcpy(ack_raw, ss5_conn->raw, ss5_conn->raw_len);
    ack_raw[1] = type;
    bool rt = tcp_send(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id, (const char *)ack_raw, ss5_conn->raw_len);
    if (!rt) {
        close_ss5_conn(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id);
    }
    _FREE_IF(ack_raw);
    return rt;
}

void on_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
    _LOG("on_resolved");

    IF_UV_ERROR(status, "on resolve domain error", {
        _FREE_IF(req);
        return;
    });

    resolver_req_t *req_ex = (resolver_req_t *)req;
    IF_GET_TCP_CONN(tcp_conn, req_ex->tcp, req_ex->conn_id, {
        _FREE_IF(req);
        return;
    });

    socks5_connection_t *ss5_conn = (socks5_connection_t *)tcp_conn->data;
    assert(ss5_conn);

    socks5_server_t *socks5 = (socks5_server_t *)ss5_conn->socks5;
    assert(socks5);

    if (res->ai_family == AF_INET) {
        // ipv4
        uv_ip4_name((struct sockaddr_in *)res->ai_addr, ss5_conn->ip, 16);
        if (!connect_tcp(socks5->tcp, ss5_conn->ip, ss5_conn->port, ss5_conn)) {
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

    // ss5_conn->resolver = NULL;
    _FREE_IF(req);
}

bool resolve_domain(uv_loop_t *loop, socks5_connection_t *ss5_conn, char *domain, int family) {
    _LOG("resolve_domain %d", ss5_conn->fr_conn->id);
    struct addrinfo hints;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

    resolver_req_t *req = (resolver_req_t *)_CALLOC(1, sizeof(resolver_req_t));
    req->conn_id = ss5_conn->fr_conn->id;
    req->tcp = ss5_conn->socks5->tcp;

    int r = uv_getaddrinfo(loop, (uv_getaddrinfo_t *)req, on_resolved, domain, NULL, &hints);
    IF_UV_ERROR(r, "resolve domain error", {
        _FREE_IF(req);
        return false;
    });

    return true;
}

static void ss5_auth(const u_char *buf, ssize_t size, socks5_connection_t *ss5_conn) {
    if (*buf != SS5_VER || size < 3) {
        goto ss5_auth_error;
    }
    u_char nmethods = buf[1];

    char ok[2] = {SS5_VER, 0x00};
    for (u_char i = 0; i < nmethods; i++) {
        if (buf[2 + i] == 0x00) {
            // NO AUTHENTICATION REQUIRED
            bool rt = tcp_send(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id, ok, 2);
            if (!rt) {
                close_ss5_conn(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id);
            } else {
                ss5_conn->phase = SS5_PHASE_REQ;
            }
            break;
        } else if (buf[2 + i] == 0x02) {
            // USERNAME/PASSWORD
            ok[1] = 0x02;
            bool rt = tcp_send(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id, ok, 2);
            if (!rt) {
                close_ss5_conn(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id);
            } else {
                ss5_conn->phase = SS5_PHASE_AUTH_NP;
            }
            break;
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
    bool rt = tcp_send(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id, ok, 2);
    if (!rt) {
        close_ss5_conn(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id);
    }
    ss5_conn->phase = SS5_PHASE_REQ;
    return;

ss5_auth_name_pwd_error:
    fprintf(stderr, "socks5 auth name password error\n");
}

static void on_back_connect(tcp_t *tcp, int conn_id) {
    _LOG("back connect ok");
    IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    socks5_connection_t *ss5_conn = (socks5_connection_t *)tcp_conn->data;
    assert(ss5_conn);
    ss5_conn->bk_conn = tcp_conn;
    if (ss5_req_ack(ss5_conn, SS5_REP_OK)) {
        ss5_conn->phase = SS5_PHASE_DATA;
        return;
    }
    close_ss5_conn(tcp, conn_id);
}

static void on_back_recv(socks5_connection_t *ss5_conn, const char *buf, ssize_t size) {
    bool rt = tcp_send(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id, buf, size);
    if (!rt) {
        close_ss5_conn(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id);
    }
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

    socks5_server_t *socks5 = (socks5_server_t *)ss5_conn->socks5;
    assert(socks5);
    u_char atyp = buf[3];
    if (atyp == SS5_ATYP_IPV4) {
        ss5_conn->port = ntohs(*(uint16_t *)(buf + 8));

        ss5_conn->raw_len = size;
        ss5_conn->raw = (u_char *)_CALLOC(1, size);
        _CHECK_OOM(ss5_conn->raw);
        memcpy(ss5_conn->raw, buf, size);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = *(in_addr_t *)(buf + 4);
        uv_ip4_name((const struct sockaddr_in *)&addr, ss5_conn->ip, 16);
        if (!connect_tcp(socks5->tcp, ss5_conn->ip, ss5_conn->port, ss5_conn)) {
            // error
            ss5_req_ack(ss5_conn, SS5_REP_ERR);
            close_ss5_conn(socks5->tcp, ss5_conn->fr_conn->id);
        }
    } else if (atyp == SS5_ATYP_IPV6) {
        _LOG("ss5 ipv6 type");
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
            close_ss5_conn(socks5->tcp, ss5_conn->fr_conn->id);
        }
        _FREE_IF(domain);
    } else {
        goto ss5_auth_req_error;
    }

    return;

ss5_auth_req_error:
    fprintf(stderr, "socks5 request error\n");
}

static void on_front_recv(socks5_connection_t *ss5_conn, const char *buf, ssize_t size) {
    _LOG("on front recv");
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
            _LOG("phase data send id:%d", ss5_conn->bk_conn->id);
            rt = tcp_send(ss5_conn->socks5->tcp, ss5_conn->bk_conn->id, buf, size);
            if (!rt) {
                close_ss5_conn(ss5_conn->socks5->tcp, ss5_conn->bk_conn->id);
            }
            break;
        default:
            break;
    }
}

static void on_front_accept(tcp_t *tcp, int conn_id) {
    _LOG("on front accept");
    IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    socks5_server_t *socks5 = (socks5_server_t *)tcp->data;
    assert(socks5);
    socks5_connection_t *ss5_conn = (socks5_connection_t *)_CALLOC(1, sizeof(socks5_connection_t));
    _CHECK_OOM(ss5_conn);
    ss5_conn->phase = SS5_PHASE_AUTH;
    ss5_conn->fr_conn = tcp_conn;
    ss5_conn->socks5 = socks5;
    tcp_conn->data = ss5_conn;
}

static void on_tcp_close(tcp_t *tcp, int conn_id) {
    _LOG("on tcp close %d", conn_id);
    IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    socks5_server_t *socks5 = (socks5_server_t *)tcp->data;
    assert(socks5);
    socks5_connection_t *ss5_conn = (socks5_connection_t *)tcp_conn->data;
    if (!ss5_conn) {
        _LOG("on tcp close ss5_conn is NULL %d", conn_id);
        return;
    }

    assert(ss5_conn);
    // close_ss5_conn(tcp, conn_id);
    if (ss5_conn->fr_conn) {
        if (ss5_conn->fr_conn->id != conn_id) {
            close_tcp_connection(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id);
        } else {
            ss5_conn->fr_conn->data = NULL;
            ss5_conn->fr_conn = NULL;
        }
    }
    if (ss5_conn->bk_conn) {
        if (ss5_conn->bk_conn->id != conn_id) {
            close_tcp_connection(ss5_conn->socks5->tcp, ss5_conn->bk_conn->id);
        } else {
            ss5_conn->bk_conn->data = NULL;
            ss5_conn->bk_conn = NULL;
        }
    }

    // if (ss5_conn->fr_conn && ss5_conn->fr_conn->id != conn_id) {
    //     close_tcp_connection(ss5_conn->socks5->tcp, ss5_conn->fr_conn->id);
    // } else {
    //     ss5_conn->fr_conn->data = NULL;
    //     ss5_conn->fr_conn = NULL;
    // }
    // if (ss5_conn->bk_conn && ss5_conn->bk_conn->id != conn_id) {
    //     close_tcp_connection(ss5_conn->socks5->tcp, ss5_conn->bk_conn->id);
    // } else {
    //     ss5_conn->bk_conn->data = NULL;
    //     ss5_conn->bk_conn = NULL;
    // }

    if (!ss5_conn->fr_conn && !ss5_conn->bk_conn) {
        free_ss5_conn(ss5_conn);
    }
}

static void on_tcp_recv(tcp_t *tcp, int conn_id, const char *buf, ssize_t size) {
    _LOG("on tcp recv");
    IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
    socks5_server_t *socks5 = (socks5_server_t *)tcp->data;
    assert(socks5);
    socks5_connection_t *ss5_conn = (socks5_connection_t *)tcp_conn->data;
    assert(ss5_conn);
    if (tcp_conn->mode == TCP_CONN_MODE_SERV) {
        on_front_recv(ss5_conn, buf, size);
    }
    if (tcp_conn->mode == TCP_CONN_MODE_CLI) {
        on_back_recv(ss5_conn, buf, size);
    }

    // TODO:
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

socks5_server_t *init_socks5_server(uv_loop_t *loop, const char *ip, uint16_t port) {
    if (!loop || !ip || port <= 0) {
        return NULL;
    }
    tcp_t *tcp = init_tcp(loop, NULL, on_front_accept, on_back_connect, on_tcp_recv, on_tcp_close);
    if (!tcp) {
        return NULL;
    }
    bool rt = start_tcp_server(tcp, ip, port);
    if (!rt) {
        free_tcp(tcp);
        return NULL;
    }
    socks5_server_t *socks5 = (socks5_server_t *)_CALLOC(1, sizeof(socks5_server_t));
    _CHECK_OOM(socks5);
    tcp->data = socks5;
    socks5->loop = loop;
    socks5->tcp = tcp;
    return socks5;
}

void free_socks5_server(socks5_server_t *socks5) {
    if (!socks5) {
        return;
    }

    if (socks5->tcp) {
        stop_tcp_server(socks5->tcp);
        free_tcp(socks5->tcp);
    }

    free(socks5);
}
