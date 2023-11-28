#include "socks5_server.h"

#include "utils.h"

/* -------------------------------------------------------------------------- */
/*                               socks5 protocol                              */
/* -------------------------------------------------------------------------- */

// #define SS5_VER 0x05
// #define SS5_MSG_AUTH 1
// #define SS5_MSG_AUTH_ACK 2
// #define SS5_MSG_AUTH_SUB 3
// #define SS5_MSG_AUTH_SUB_ACK 4
// #define SS5_MSG_AUTH_REQ 5
// #define SS5_MSG_AUTH_REQ_ACK 6

// // +----+----------+----------+
// // |VER | NMETHODS | METHODS  |
// // +----+----------+----------+
// // | 1  |    1     | 1 to 255 |
// // +----+----------+----------+
// typedef struct {
//     u_char ver;
//     u_char nmethods;
//     u_char method[255];
// } ss5_auth_t;

// // +----+--------+
// // |VER | METHOD |
// // +----+--------+
// // | 1  |   1    |
// // +----+--------+
// typedef struct {
//     u_char ver;
//     u_char method;
// } ss5_auth_ack_t;

// // +----+------+----------+------+----------+
// // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// // +----+------+----------+------+----------+
// // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
// // +----+------+----------+------+----------+
// typedef struct {
//     u_char ver;
//     u_char ulen;
//     u_char plen;
//     u_char uname[255];
//     u_char passwd[255];
// } ss5_auth_sub_t;

// // +----+-----+-------+------+----------+----------+
// // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// // +----+-----+-------+------+----------+----------+
// // | 1  |  1  | X'00' |  1   | Variable |    2     |
// // +----+-----+-------+------+----------+----------+
// typedef struct {
//     u_char ver;
//     u_char cmd;
//     u_char rsv;
//     u_char atyp;
//     u_char *dst_addr;
//     uint16_t dst_port;
// } ss5_req_t;

// // +----+-----+-------+------+----------+----------+
// // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// // +----+-----+-------+------+----------+----------+
// // | 1  |  1  | X'00' |  1   | Variable |    2     |
// // +----+-----+-------+------+----------+----------+
// typedef struct {
//     u_char ver;
//     u_char rep;
//     u_char rsv;
//     u_char atyp;
//     u_char *bnd_addr;
//     uint16_t bnd_port;
// } ss5_req_ack_t;

// // typedef struct {
// //     int type;
// //     u_char ver;
// //     u_char nmethods;
// //     u_char methods[255];
// //     u_char method;
// //     u_char ulen;
// //     u_char plen;
// //     u_char uname[255];
// //     u_char passwd[255];

// //     u_char rep;
// //     u_char rsv;
// //     u_char atyp;
// //     u_char addr;
// //     uint16_t port;
// // } ss5_msg_t;

// static u_char *pack_ss5_auth(const ss5_auth_t *msg, int *len) {
//     if (!msg || !len) {
//         return NULL;
//     }
//     *len = msg->nmethods + 2;
//     u_char *raw = (u_char *)_CALLOC(1, *len);
//     _CHECK_OOM(raw);
//     raw[0] = SS5_VER;
//     raw[1] = msg->nmethods;
//     memcpy(raw + 2, msg->method, msg->nmethods);
//     return raw;
// }

// static ss5_auth_t *unpack_ss5_auth(const u_char *buf, int len) {
//     if (!buf || len <= 2) {
//         return NULL;
//     }
//     ss5_auth_t *msg = (ss5_auth_t *)_CALLOC(1, sizeof(ss5_auth_t));
//     msg->ver = *buf;
//     msg->nmethods = *(buf + 1);
//     memcpy(msg->method, buf + 2, msg->nmethods);
//     return msg;
// }

// static u_char *pack_ss5_auth_ack(const ss5_auth_ack_t *msg, int *len) {
//     if (!msg || !len) {
//         return NULL;
//     }
//     *len = 2;
//     u_char *raw = (u_char *)_CALLOC(1, 2);
//     _CHECK_OOM(raw);
//     raw[0] = SS5_VER;
//     raw[1] = msg->method;
//     return raw;
// }

// static ss5_auth_ack_t *unpack_ss5_auth_ack(const u_char *buf, int len) {
//     if (!buf || len <= 2) {
//         return NULL;
//     }
//     ss5_auth_ack_t *msg = (ss5_auth_ack_t *)_CALLOC(1, sizeof(ss5_auth_ack_t));
//     msg->ver = *buf;
//     msg->method = *(buf + 1);
//     return msg;
// }

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

static void free_ss5_conn(socks5_connection_t *conn) {
    // TODO:
}

static void ss5_auth(const u_char *buf, ssize_t size, tcp_connection_t *tcp_conn) {
    if (*buf != SS5_VER || size < 3) {
        goto ss5_auth_error;
    }
    u_char nmethods = buf[1];

    socks5_connection_t *ss5_conn = (socks5_connection_t *)tcp_conn->data;
    char ok[2] = {SS5_VER, 0x00};
    for (u_char i = 0; i < nmethods; i++) {
        if (buf[2] == 0x00) {
            tcp_send(tcp_conn, ok, 2);
            ss5_conn->phase = SS5_PHASE_REQ;
        }
        if (buf[2] == 0x02) {
            tcp_send(tcp_conn, ok, 2);
            ss5_conn->phase = SS5_PHASE_AUTH_NP;
        }
    }
    return;

ss5_auth_error:
    fprintf(stderr, "socks5 auth error\n");
}

static void ss5_auth_np(const u_char *buf, ssize_t size, tcp_connection_t *tcp_conn) {
    if (*buf != SS5_VER || size < 5) {
        goto ss5_auth_name_pwd_error;
    }
    char ok[2] = {SS5_VER, 0x00};
    tcp_send(tcp_conn, ok, 2);
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

static void on_client_connect(tcp_connection_t *conn) {
    _LOG("connect ok");
    socks5_connection_t *ss5_conn = (socks5_connection_t *)conn->data;
    ss5_conn->bk_conn = conn;

    u_char *ack_raw = (u_char *)_CALLOC(1, ss5_conn->raw_len);
    memcpy(ack_raw, ss5_conn->raw, ss5_conn->raw_len);
    ack_raw[1] = SS5_REP_OK;
    tcp_send(ss5_conn->fr_conn, ack_raw, ss5_conn->raw_len);
    _FREE_IF(ack_raw);
}

static void on_client_recv(tcp_connection_t *conn, const char *buf, ssize_t size) {
    // _LOG("recv:%s", buf);
    bool rt = tcp_send(conn, buf, size);
    assert(rt);
    // TODO:
}

static void on_client_close(tcp_connection_t *conn) {
    _LOG("close %d", conn->id);
    // TODO:
}

static void ss5_req(const u_char *buf, ssize_t size, socks5_connection_t *ss5_conn) {
    if (*buf != SS5_VER || size < 7) {
        goto ss5_auth_req_error;
    }

    u_char cmd = buf[1];
    if (cmd == SS5_CMD_BIND || cmd == SS5_CMD_UDP_ASSOCIATE) {
        // TODO: support bind and udp associate
        _LOG("now only 'connect' command is supported.");
        return;
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
        uint16_t port = ntohs((uint16_t)(buf[7]));

        ss5_conn->raw_len = size;
        ss5_conn->raw = (u_char *)_CALLOC(1, size);
        _CHECK_OOM(ss5_conn->raw);
        memcpy(ss5_conn->raw, buf, size);

        // memcpy(ss5_conn->port_raw, buf[7], 2);
        // ss5_conn->addr_raw_len = 4;
        // ss5_conn->addr_raw = (u_char *)_CALLOC(1, ss5_conn->addr_raw_len);
        // memcpy(ss5_conn->addr_raw, buf[4], ss5_conn->addr_raw_len);
        char ip[17] = {0};
        struct sockaddr_in addr = *(struct sockaddr_in *)buf[4];  // TODO: ntoh?
        uv_ip4_name((const struct sockaddr_in *)&addr, ip, 16);
        if (!tcp_connect(socks5->loop, ip, port, ss5_conn, on_client_connect, on_client_recv, on_client_close)) {
            // error
            u_char *ack_raw = (u_char *)_CALLOC(1, ss5_conn->raw_len);
            memcpy(ack_raw, ss5_conn->raw, ss5_conn->raw_len);
            ack_raw[1] = SS5_REP_ERR;
            tcp_send(ss5_conn->fr_conn, ack_raw, ss5_conn->raw_len);
            _FREE_IF(ack_raw);
        }
    } else if (atyp == SS5_ATYP_IPV6) {
        // u_char dst_addr[16] = {0};
        uint16_t port = ntohs((uint16_t)buf[19]);
        // TODO: connect to dest
    } else if (atyp == SS5_ATYP_DOMAIN) {
        // TODO: resolve DNS
        // TODO: connect to dest
    } else {
        goto ss5_auth_req_error;
    }

    return;

ss5_auth_req_error:
    fprintf(stderr, "socks5 request error\n");
}

static void on_server_close(tcp_connection_t *conn) {
    _LOG("on_tcp_close");
    socks5_server_t *socks5 = (socks5_server_t *)conn->serv->data;
    // socks5->on_close((socks5_connection_t *)conn->data);
}

static void on_server_recv(tcp_connection_t *conn, const char *buf, ssize_t size) {
    _LOG("on_tcp_recv");
    socks5_server_t *socks5 = (socks5_server_t *)conn->serv->data;
    socks5_connection_t *ss5_conn = (socks5_connection_t *)conn->data;
    switch (ss5_conn->phase) {
        case SS5_PHASE_AUTH:
            ss5_auth((const u_char *)buf, size, conn);
            break;
        case SS5_PHASE_AUTH_NP:
            ss5_auth_np((const u_char *)buf, size, conn);
            break;
        case SS5_PHASE_REQ:
            ss5_req((const u_char *)buf, size, ss5_conn);
            break;
        case SS5_PHASE_DATA:
            // socks5->on_recv(conn, buf, size);
            // TODO:
            break;
        default:
            break;
    }
}

static void on_server_accept(tcp_connection_t *conn) {
    _LOG("on_tcp_accept");
    // tcp_server_t *tcp_serv = conn->serv
    socks5_server_t *socks5 = (socks5_server_t *)conn->serv->data;
    socks5_connection_t *ss5_conn = (socks5_connection_t *)_CALLOC(1, sizeof(socks5_connection_t));
    ss5_conn->phase = SS5_PHASE_AUTH;
    ss5_conn->fr_conn = conn;
    conn->data = ss5_conn;
    // socks5->on_accept(ss5_conn);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

socks5_server_t *init_socks5_server(uv_loop_t *loop, const char *ip, uint16_t port) {
    if (!loop || !ip || port <= 0) {
        return NULL;
    }

    tcp_server_t *tcp_serv = init_tcp_server(loop, ip, port, NULL, on_server_accept, on_server_recv, on_server_close);
    if (!tcp_serv) {
        return NULL;
    }

    socks5_server_t *socks5 = (socks5_server_t *)_CALLOC(1, sizeof(socks5_server_t));
    _CHECK_OOM(socks5);
    tcp_serv->data = socks5;
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

// bool socks5_server_send(socks5_connection_t *conn, const char *buf, ssize_t size) {
//     if (!conn || !buf || size <= 0) {
//         return false;
//     }

//     // TODO: wrap buf
//     return tcp_server_send(socks5->tcp_serv, conn_id, buf, size);
// }

/* -------------------------------------------------------------------------- */
/*                                    test                                    */
/* -------------------------------------------------------------------------- */

// int main(int argc, char const *argv[]) {
//     uv_loop_t *loop = uv_default_loop();
//     socks5_server_t *socks5 = init_socks5_server(loop, "127.0.0.1", 6666, NULL, NULL, NULL);
//     assert(socks5);
//     return uv_run(loop, UV_RUN_DEFAULT);
// }
