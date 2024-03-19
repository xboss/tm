#include "socks5_server.h"

#include "cipher.h"
#include "utils.h"

/* -------------------------------------------------------------------------- */
/*                                   server                                   */
/* -------------------------------------------------------------------------- */
#define SS5_VER 0x05U
#define SS5_AUTH_NP_VER 0x01U
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

static char iv[CIPHER_IV_LEN + 1] = {0};

struct socks5_server_s {
    uv_loop_t *loop;
    n2n_t *n2n;
    char *key;
    int socks5_auth_mode;  // 0:no auth; 1:username/password
    on_auth_socks5_user_t on_auth_socks5_user;
};

typedef struct {
    uv_getaddrinfo_t resolver;
    n2n_t *n2n;
    int conn_id;
} resolver_req_t;

static socks5_conn_t *clone_ss5_conn(socks5_conn_t *conn) {
    socks5_conn_t *new_conn = (socks5_conn_t *)_CALLOC(1, sizeof(socks5_conn_t));
    _CHECK_OOM(new_conn);
    memcpy(new_conn, conn, sizeof(socks5_conn_t));
    if (conn->raw_len > 0) {
        new_conn->raw = (u_char *)_CALLOC(1, conn->raw_len);
        _CHECK_OOM(new_conn->raw);
        memcpy(new_conn->raw, conn->raw, conn->raw_len);
    }
    return new_conn;
}

#define PREPARE_SS5_INFO                                       \
    assert(n2n_conn);                                          \
    socks5_conn_t *ss5_conn = (socks5_conn_t *)n2n_conn->data; \
    assert(ss5_conn);                                          \
    socks5_server_t *socks5 = ss5_conn->socks5;                \
    assert(socks5);                                            \
    n2n_t *n2n = socks5->n2n;                                  \
    assert(n2n)

static void free_ss5_conn(socks5_conn_t *conn) {
    _LOG("free_ss5_conn");
    assert(conn);
    conn->phase = -9999;  // TODO: test
    if (conn->raw) {
        _FREE_IF(conn->raw);
    }
    _FREE_IF(conn);
    _LOG("free_ss5_conn end");
}

static inline bool send_to_front(socks5_server_t *socks5, n2n_t *n2n, int conn_id, const char *buf, ssize_t size) {
    char *cipher_txt = (char *)buf;
    int cipher_txt_len = size;
    if (socks5->key) {
        // bzero(iv, CIPHER_IV_LEN);
        memset(iv, 0, CIPHER_IV_LEN);
        cipher_txt = aes_encrypt(socks5->key, iv, buf, size, &cipher_txt_len);
    }

    int msg_len = 0;
    char *msg_buf = n2n_pack_msg(cipher_txt, cipher_txt_len, &msg_len);
    if (socks5->key) {
        _FREE_IF(cipher_txt);
    }
    bool rt = n2n_send_to_front(n2n, conn_id, msg_buf, msg_len);
    _FREE_IF(msg_buf);
    return rt;
}

static bool ss5_req_ack(socks5_server_t *socks5, int conn_id, u_char type, u_char *raw, ssize_t raw_len, n2n_t *n2n) {
    // printf("raw:\n");
    // for (size_t i = 0; i < raw_len; i++) {
    //     printf("%X ", raw[i]);
    // }
    // printf("\n");

    u_char *ack_raw = (u_char *)_CALLOC(1, raw_len);
    _CHECK_OOM(ack_raw);
    memcpy(ack_raw, raw, raw_len);
    ack_raw[1] = type;

    // printf("ack_raw:\n");
    // for (size_t i = 0; i < raw_len; i++) {
    //     printf("%X ", ack_raw[i]);
    // }
    // printf("\n");

    bool rt = send_to_front(socks5, n2n, conn_id, (const char *)ack_raw, raw_len);
    if (!rt) {
        n2n_close_conn(n2n, conn_id);
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
    IF_GET_N2N_CONN(n2n_conn, req_ex->n2n, req_ex->conn_id, {
        // connection has been closed
        _FREE_IF(req);
        return;
    });

    PREPARE_SS5_INFO;

    if (res->ai_family == AF_INET) {
        // ipv4
        in_port_t sin_port = ss5_conn->target_addr.sin_port;

        // uint16_t port = ntohs(sin_port);  // TODO: test
        // _LOG("port: %u", port);

        ss5_conn->target_addr = (*(struct sockaddr_in *)res->ai_addr);
        ss5_conn->target_addr.sin_port = sin_port;
        socks5_conn_t *new_ss5_conn = clone_ss5_conn(ss5_conn);
        int bk_id = n2n_connect_backend(n2n, ss5_conn->target_addr, n2n_conn->conn_id, new_ss5_conn);
        if (bk_id <= 0) {
            free_ss5_conn(new_ss5_conn);
            ss5_req_ack(socks5, n2n_conn->conn_id, SS5_REP_ERR, ss5_conn->raw, ss5_conn->raw_len, n2n);
            _FREE_IF(req);
            return;
        }
        // new_ss5_conn->n2n_conn = n2n_get_conn(socks5->n2n, bk_id);
    } else if (res->ai_family == AF_INET6) {
        // ipv6
        // TODO:
    } else {
        // ipv4 or ipv6
        // TODO:
    }

    _FREE_IF(req);
    _LOG("on_resolved end");
}

bool resolve_domain(uv_loop_t *loop, n2n_conn_t *n2n_conn, char *domain, int family) {
    PREPARE_SS5_INFO;
    _LOG("resolve_domain %d", n2n_conn->conn_id);
    struct addrinfo hints;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

    resolver_req_t *req = (resolver_req_t *)_CALLOC(1, sizeof(resolver_req_t));
    _CHECK_OOM(req);
    req->conn_id = n2n_conn->conn_id;
    req->n2n = socks5->n2n;

    int r = uv_getaddrinfo(loop, (uv_getaddrinfo_t *)req, on_resolved, domain, NULL, &hints);
    IF_UV_ERROR(r, "resolve domain error", {
        _FREE_IF(req);
        return false;
    });

    return true;
}

static void ss5_auth(const u_char *buf, ssize_t size, n2n_conn_t *n2n_conn) {
    PREPARE_SS5_INFO;

    if (*buf != SS5_VER || size < 3) {
        _ERR("socks5 auth error %d %c %ld", n2n_conn->conn_id, *buf, size);
        n2n_close_conn(n2n, n2n_conn->conn_id);
        return;
    }
    int nmethods = (int)buf[1];
    char ok[2] = {SS5_VER, 0x00};
    for (int i = 0; i < nmethods; i++) {
        if (buf[2 + i] == 0x00 && socks5->socks5_auth_mode == 0) {
            // NO AUTHENTICATION REQUIRED
            if (!send_to_front(socks5, n2n, n2n_conn->conn_id, ok, 2)) {
                n2n_close_conn(n2n, n2n_conn->conn_id);
                return;
            } else {
                ss5_conn->phase = SS5_PHASE_REQ;
            }
            break;
        } else if (buf[2 + i] == 0x02 && socks5->socks5_auth_mode == 1) {
            // USERNAME/PASSWORD
            ok[1] = 0x02;
            if (!send_to_front(socks5, n2n, n2n_conn->conn_id, ok, 2)) {
                n2n_close_conn(n2n, n2n_conn->conn_id);
                return;
            } else {
                ss5_conn->phase = SS5_PHASE_AUTH_NP;
            }
            break;
        }
    }
    if (ss5_conn->phase == SS5_PHASE_AUTH) {
        n2n_close_conn(n2n, n2n_conn->conn_id);
        return;
    }
}

static void ss5_auth_np(const u_char *buf, ssize_t size, n2n_conn_t *n2n_conn) {
    PREPARE_SS5_INFO;
    _LOG("ss5_auth_np %d", n2n_conn->conn_id);
    if (*buf != SS5_AUTH_NP_VER || size < 5) {
        _ERR("socks5 auth name password error");
        n2n_close_conn(n2n, n2n_conn->conn_id);
        return;
    }
    int name_len = buf[1];
    if (name_len < 0) {
        _ERR("socks5 auth name length error");
        n2n_close_conn(n2n, n2n_conn->conn_id);
        return;
    }
    // assert(name_len >= 0);
    int pwd_len = buf[2 + name_len];
    if (pwd_len < 0) {
        _ERR("socks5 auth password length error");
        n2n_close_conn(n2n, n2n_conn->conn_id);
        return;
    }
    // assert(pwd_len >= 0);
    // char tmp[UCHAR_MAX + 1] = {0};
    // char *name = _CALLOC(1, name_len + 1);
    // _CHECK_OOM(name);
    // memcpy(tmp, buf + 2, name_len);
    // _LOG("name: %s", name);
    // char *pwd = _CALLOC(1, pwd_len + 1);
    // _CHECK_OOM(pwd);
    // memcpy(pwd, buf + 3 + name_len, pwd_len);
    // _LOG("pwd: %s", pwd);
    int auth_rt = 0;
    if (socks5->on_auth_socks5_user) {
        auth_rt =
            socks5->on_auth_socks5_user((const char *)(buf + 2), name_len, (const char *)(buf + 3 + name_len), pwd_len);
    }
    // _FREE_IF(name);
    // _FREE_IF(pwd);
    char msg[2] = {SS5_AUTH_NP_VER, 0x00};
    if (auth_rt != 0) {
        msg[1] = 0x01;
    }
    if (!send_to_front(socks5, n2n, n2n_conn->conn_id, msg, 2) || auth_rt != 0) {
        _LOG("ss5_auth_np error %d", n2n_conn->conn_id);
        n2n_close_conn(n2n, n2n_conn->conn_id);
        return;
    }
    ss5_conn->phase = SS5_PHASE_REQ;
    _LOG("ss5_auth_np ok %d", n2n_conn->conn_id);
}

static void ss5_req(const u_char *buf, ssize_t size, n2n_conn_t *n2n_conn) {
    PREPARE_SS5_INFO;

    if (*buf != SS5_VER || size < 7) {
        _ERR("socks5 request error version %X size: %ld", *buf, size);
        return;
        // goto ss5_auth_req_error;
    }

    u_char cmd = buf[1];
    if (cmd == SS5_CMD_BIND || cmd == SS5_CMD_UDP_ASSOCIATE) {
        // TODO: support bind and udp associate
        _LOG("now only 'connect' command is supported.");
        return;
    }
    if (cmd != SS5_CMD_CONNECT) {
        _ERR("socks5 request error cmd");
        return;
    }

    u_char atyp = buf[3];
    if (atyp == SS5_ATYP_IPV4) {
        ss5_conn->raw_len = size;
        ss5_conn->raw = (u_char *)_CALLOC(1, size);
        _CHECK_OOM(ss5_conn->raw);
        memcpy(ss5_conn->raw, buf, size);
        // struct sockaddr_in addr;
        ss5_conn->target_addr.sin_family = AF_INET;
        ss5_conn->target_addr.sin_addr.s_addr = *(in_addr_t *)(buf + 4);
        memcpy(&(ss5_conn->target_addr.sin_port), buf + 8, sizeof(ss5_conn->target_addr.sin_port));
        socks5_conn_t *new_ss5_conn = clone_ss5_conn(ss5_conn);
        int bk_id = n2n_connect_backend(n2n, ss5_conn->target_addr, n2n_conn->conn_id, new_ss5_conn);
        if (bk_id <= 0) {
            free_ss5_conn(new_ss5_conn);
            ss5_req_ack(socks5, n2n_conn->conn_id, SS5_REP_ERR, ss5_conn->raw, ss5_conn->raw_len, n2n);
            _ERR("socks5 request error connect backend");
            return;
        }
    } else if (atyp == SS5_ATYP_IPV6) {
        _LOG("ss5 ipv6 type");
        // uint16_t port = ntohs((uint16_t)buf[19]);
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

        memcpy(&(ss5_conn->target_addr.sin_port), buf + 4 + d_len + 1, sizeof(ss5_conn->target_addr.sin_port));
        _LOG("%s", domain);
        // resolve DNS
        if (!resolve_domain(socks5->loop, n2n_conn, domain, AF_INET)) {
            _FREE_IF(domain);
            ss5_req_ack(socks5, n2n_conn->conn_id, SS5_REP_HOST_ERR, ss5_conn->raw, ss5_conn->raw_len, n2n);
            _ERR("socks5 request error resolve domain");
            return;
        }
        _FREE_IF(domain);
    } else {
        _ERR("socks5 request error atyp");
        return;
    }
}

/* -------------------------------------------------------------------------- */
/*                                  callback                                  */
/* -------------------------------------------------------------------------- */

#define GET_SS5_INFO                                        \
    socks5_server_t *socks5 = (socks5_server_t *)n2n->data; \
    assert(socks5);                                         \
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {});            \
    assert(n2n_conn)

#define GET_SS5_INFO_ALL                                       \
    GET_SS5_INFO;                                              \
    socks5_conn_t *ss5_conn = (socks5_conn_t *)n2n_conn->data; \
    assert(ss5_conn)

void on_n2n_front_accept(n2n_t *n2n, int conn_id) {
    _LOG("on_n2n_front_accept %d", conn_id);
    GET_SS5_INFO;
    socks5_conn_t *ss5_conn = (socks5_conn_t *)_CALLOC(1, sizeof(socks5_conn_t));
    _CHECK_OOM(ss5_conn);
    n2n_conn->data = ss5_conn;
    ss5_conn->phase = SS5_PHASE_AUTH;
    ss5_conn->socks5 = socks5;
}

void on_n2n_close(n2n_t *n2n, int conn_id) {
    _LOG("on_n2n_close %d", conn_id);
    GET_SS5_INFO_ALL;
    n2n_conn->data = NULL;
    free_ss5_conn(ss5_conn);
}

void on_read_n2n_msg(const char *buf, ssize_t size, n2n_conn_t *n2n_conn) {
    IF_GET_N2N_CONN(test_conn, n2n_conn->n2n, n2n_conn->conn_id, { assert(0); });  // TODO: for test
    socks5_conn_t *ss5_conn = (socks5_conn_t *)n2n_conn->data;
    assert(ss5_conn);
    socks5_server_t *socks5 = ss5_conn->socks5;
    assert(socks5);

    char *plan_txt = (char *)buf;
    int plan_txt_len = size;
    if (socks5->key) {
        // bzero(iv, CIPHER_IV_LEN);
        memset(iv, 0, CIPHER_IV_LEN);
        plan_txt = aes_decrypt(socks5->key, iv, buf, size, &plan_txt_len);
    }
    // _PR(plan_txt, plan_txt_len);

    n2n_t *n2n = n2n_conn->n2n;
    // int conn_id = n2n_conn->conn_id;
    switch (ss5_conn->phase) {
        case SS5_PHASE_AUTH:
            ss5_auth((const u_char *)plan_txt, plan_txt_len, n2n_conn);
            break;
        case SS5_PHASE_AUTH_NP:
            ss5_auth_np((const u_char *)plan_txt, plan_txt_len, n2n_conn);
            break;
        case SS5_PHASE_REQ:
            ss5_req((const u_char *)plan_txt, plan_txt_len, n2n_conn);
            break;
        case SS5_PHASE_DATA:
            // _LOG("phase data send id: %d", conn_id);
            if (!n2n_send_to_back(n2n, n2n_conn->couple_id, plan_txt, plan_txt_len)) {
                n2n_close_conn(n2n, n2n_conn->couple_id);
            }
            break;
        default:
            break;
    }
    if (socks5->key) {
        _FREE_IF(plan_txt);
    }
}

void on_n2n_front_recv(n2n_t *n2n, int conn_id, const char *buf, ssize_t size) {
    _LOG("on_n2n_front_recv %d", conn_id);
    GET_SS5_INFO_ALL;

    int rt = n2n_read_msg(buf, size, n2n_conn, on_read_n2n_msg);
    if (rt < 0) {
        // error
        _LOG("msg format error %d", conn_id);
        return;
    }

    // switch (ss5_conn->phase) {
    //     case SS5_PHASE_AUTH:
    //         ss5_auth((const u_char *)buf, size, n2n_conn);
    //         break;
    //     case SS5_PHASE_AUTH_NP:
    //         ss5_auth_np((const u_char *)buf, size, n2n_conn);
    //         break;
    //     case SS5_PHASE_REQ:
    //         ss5_req((const u_char *)buf, size, n2n_conn);
    //         break;
    //     case SS5_PHASE_DATA:
    //         _LOG("phase data send id: %d", conn_id);
    //         if (!n2n_send_to_back(n2n, n2n_conn->couple_id, buf, size)) {
    //             n2n_close_conn(n2n, n2n_conn->couple_id);
    //         }
    //         break;
    //     default:
    //         break;
    // }
}

void on_n2n_backend_recv(n2n_t *n2n, int conn_id, const char *buf, ssize_t size) {
    _LOG("on_n2n_backend_recv %d", conn_id);
    GET_SS5_INFO_ALL;
    if (!send_to_front(socks5, n2n, n2n_conn->couple_id, buf, size)) {
        n2n_close_conn(n2n, conn_id);
    }
}

void on_n2n_backend_connect(n2n_t *n2n, int conn_id) {
    _LOG("on_n2n_backend_connect %d", conn_id);
    GET_SS5_INFO_ALL;
    if (ss5_req_ack(socks5, n2n_conn->couple_id, SS5_REP_OK, ss5_conn->raw, ss5_conn->raw_len, n2n)) {
        IF_GET_N2N_CONN(n2n_couple_conn, n2n, n2n_conn->couple_id, { return; });
        socks5_conn_t *ss5_conn_front = (socks5_conn_t *)n2n_couple_conn->data;
        assert(ss5_conn_front);
        ss5_conn_front->phase = SS5_PHASE_DATA;
        _LOG("on_n2n_backend_connect ok %d", conn_id);
    }
    _LOG("on_n2n_backend_connect end %d", conn_id);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

socks5_server_t *init_socks5_server(uv_loop_t *loop, const char *ip, uint16_t port, const char *pwd,
                                    int socks5_auth_mode, on_auth_socks5_user_t on_auth_socks5_user) {
    if (!loop || !ip || port <= 0) {
        return NULL;
    }
    n2n_t *n2n = n2n_init_server(loop, ip, port, NULL, 0, on_n2n_front_accept, on_n2n_close, on_n2n_front_recv,
                                 on_n2n_backend_recv, on_n2n_backend_connect);
    if (!n2n) {
        return NULL;
    }
    socks5_server_t *socks5 = (socks5_server_t *)_CALLOC(1, sizeof(socks5_server_t));
    _CHECK_OOM(socks5);
    n2n->data = socks5;
    socks5->loop = loop;
    socks5->n2n = n2n;
    socks5->socks5_auth_mode = socks5_auth_mode;
    socks5->on_auth_socks5_user = on_auth_socks5_user;
    if (pwd) {
        socks5->key = pwd2key(pwd);
        _LOG("start cipher mode %s", socks5->key);
    }
    _LOG("socks5 server is started, listen on %s:%u", ip, port);
    return socks5;
}

void free_socks5_server(socks5_server_t *socks5) {
    if (!socks5) {
        return;
    }

    if (socks5->n2n) {
        n2n_free_server(socks5->n2n);  // TODO:
    }

    if (socks5->key) {
        _FREE_IF(socks5->key);
    }

    _FREE_IF(socks5);
}
