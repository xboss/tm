#include "socks5_server.h"

#include "tcp_server.h"
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

#define SS5_PHASE_AUTH 1
#define SS5_PHASE_REQ 2
#define SS5_PHASE_DATA 3
#define SS5_PHASE_AUTH_NP 4
// typedef enum { ss5_phase_auth = 1, ss5_phase_req, ss5_phase_data } ss5_phase;

struct socks5_server_s {
    tcp_server_t *tcp_serv;
    on_socks5_accept_t on_accept;
    on_socks5_recv_t on_recv;
    on_socks5_close_t on_close;
};

typedef struct {
    // tcp_connection_t *tcp_conn;
    int phase;
    tcp_connection_t *dst_conn;
    void *data;
} socks5_connection_t;

static void ss5_auth(const u_char *buf, ssize_t size, tcp_connection_t *tcp_conn) {
    if (*buf != SS5_VER || size < 3) {
        goto ss5_auth_error;
    }
    u_char nmethods = buf[1];

    socks5_connection_t *ss5_conn = (socks5_connection_t *)tcp_conn->data;
    char ok[2] = {SS5_VER, 0x00};
    for (u_char i = 0; i < nmethods; i++) {
        if (buf[2] == 0x00) {
            tcp_server_send(tcp_conn->tcp_serv, tcp_conn->id, ok, 2);
            ss5_conn->phase = SS5_PHASE_REQ;
        }
        if (buf[2] == 0x02) {
            tcp_server_send(tcp_conn->tcp_serv, tcp_conn->id, ok, 2);
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
    tcp_server_send(tcp_conn->tcp_serv, tcp_conn->id, ok, 2);
    return;

ss5_auth_name_pwd_error:
    fprintf(stderr, "socks5 auth name password error\n");
}

static void ss5_req(const u_char *buf, ssize_t size, tcp_connection_t *tcp_conn) {
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

    u_char atyp = buf[3];
    // u_char dst_addr[128] = {0};
    if (atyp == SS5_ATYP_IPV4) {
        u_char dst_addr[4] = {0};
        uint16_t port = ntohs((uint16_t)buf[7]);
        // TODO: connect to dest
    } else if (atyp == SS5_ATYP_IPV6) {
        u_char dst_addr[16] = {0};
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

static void on_tcp_close(tcp_server_t *tcp_serv, int conn_id) {
    _LOG("on_tcp_close");
    socks5_server_t *socks5 = (socks5_server_t *)tcp_serv->data;
    socks5->on_close(socks5, conn_id);
}

static void on_tcp_recv(tcp_server_t *tcp_serv, int conn_id, const char *buf, ssize_t size) {
    _LOG("on_tcp_recv");
    tcp_connection_t *tcp_conn = get_tcp_server_conn(tcp_serv, conn_id);
    if (!tcp_conn) {
        fprintf(stderr, "tcp server connection does not exist %d\n", conn_id);
        return;
    }
    socks5_server_t *socks5 = (socks5_server_t *)tcp_serv->data;
    socks5_connection_t *ss5_conn = (socks5_connection_t *)tcp_conn->data;
    switch (ss5_conn->phase) {
        case SS5_PHASE_AUTH:
            ss5_auth((const u_char *)buf, size, tcp_conn);
            break;
        case SS5_PHASE_AUTH_NP:
            ss5_auth_np((const u_char *)buf, size, tcp_conn);
            break;
        case SS5_PHASE_REQ:
            ss5_req((const u_char *)buf, size, tcp_conn);
            break;
        case SS5_PHASE_DATA:
            socks5->on_recv(socks5, conn_id, buf, size);
            break;

        default:
            break;
    }
}

static void on_tcp_accept(tcp_server_t *tcp_serv, int conn_id) {
    _LOG("on_tcp_accept");
    socks5_server_t *socks5 = (socks5_server_t *)tcp_serv->data;
    tcp_connection_t *tcp_conn = get_tcp_server_conn(tcp_serv, conn_id);
    if (!tcp_conn) {
        fprintf(stderr, "tcp server connection does not exist %d\n", conn_id);
        return;
    }
    socks5_connection_t *ss5_conn = (socks5_connection_t *)_CALLOC(1, sizeof(socks5_connection_t));
    ss5_conn->phase = SS5_PHASE_AUTH;
    tcp_conn->data = ss5_conn;
    socks5->on_accept(socks5, conn_id);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

socks5_server_t *init_socks5_server(uv_loop_t *loop, const char *ip, uint16_t port, on_socks5_accept_t on_accept,
                                    on_socks5_recv_t on_recv, on_socks5_close_t on_close) {
    if (!loop || !ip || port <= 0) {
        return NULL;
    }

    tcp_server_t *tcp_serv = init_tcp_server(loop, ip, port, on_tcp_accept, on_tcp_recv, on_tcp_close);
    if (!tcp_serv) {
        return NULL;
    }

    socks5_server_t *socks5 = (socks5_server_t *)_CALLOC(1, sizeof(socks5_server_t));
    _CHECK_OOM(socks5);
    tcp_serv->data = socks5;
    socks5->tcp_serv = tcp_serv;
    socks5->on_accept = on_accept;
    socks5->on_close = on_close;
    socks5->on_recv = on_recv;

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

bool socks5_server_send(socks5_server_t *socks5, int conn_id, const char *buf, ssize_t size) {
    if (!socks5 || !buf || size <= 0) {
        return false;
    }

    // TODO: wrap buf
    return tcp_server_send(socks5->tcp_serv, conn_id, buf, size);
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
