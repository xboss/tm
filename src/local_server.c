#include "local_server.h"

#include "cipher.h"
#include "utils.h"

struct local_server_s {
    uv_loop_t *loop;
    n2n_t *n2n;
    char *key;
};

static char iv[CIPHER_IV_LEN + 1] = {0};

static inline bool send_to_back(local_server_t *local, n2n_t *n2n, int conn_id, const char *buf, ssize_t size) {
    if (!buf || size <= 0) {
        return n2n_send_to_back(n2n, conn_id, buf, size);
    }
    char *cipher_txt = (char *)buf;
    int cipher_txt_len = size;
    if (local->key) {
        bzero(iv, CIPHER_IV_LEN);
        cipher_txt = aes_encrypt(local->key, iv, buf, size, &cipher_txt_len);
    }
    int msg_len = 0;
    char *msg_buf = n2n_pack_msg(cipher_txt, cipher_txt_len, &msg_len);
    if (local->key) {
        _FREE_IF(cipher_txt);
    }
    bool rt = n2n_send_to_back(n2n, conn_id, msg_buf, msg_len);
    _FREE_IF(msg_buf);
    return rt;
}

/* -------------------------------------------------------------------------- */
/*                                  callback                                  */
/* -------------------------------------------------------------------------- */

#define GET_LOCAL_INFO                                   \
    local_server_t *local = (local_server_t *)n2n->data; \
    assert(local);                                       \
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {});         \
    assert(n2n_conn)

static void on_n2n_front_accept(n2n_t *n2n, int conn_id) {
    _LOG("on_n2n_front_accept %d", conn_id);
    GET_LOCAL_INFO;
    n2n_conn->couple_id = n2n_connect_backend(n2n, n2n->target_addr, conn_id, NULL);
    if (n2n_conn->couple_id <= 0) {
        // error
        n2n_close_conn(n2n, conn_id);
        return;
    }
    n2n_conn->couple_id = n2n_conn->couple_id;
}

static void on_n2n_close(n2n_t *n2n, int conn_id) {
    _LOG("on_n2n_close %d", conn_id);
    // GET_LOCAL_INFO;
    // n2n_conn->data = NULL;
    // free_ss5_conn(ss5_conn);
}

static void on_read_n2n_msg(const char *buf, ssize_t size, n2n_conn_t *n2n_conn) {
    IF_GET_N2N_CONN(test_conn, n2n_conn->n2n, n2n_conn->conn_id, { assert(0); });  // TODO: for test
    local_server_t *local = (local_server_t *)n2n_conn->n2n->data;
    assert(local);
    char *plan_txt = (char *)buf;
    int plan_txt_len = size;
    if (local->key) {
        bzero(iv, CIPHER_IV_LEN);
        plan_txt = aes_decrypt(local->key, iv, buf, size, &plan_txt_len);
    }
    // _PR(plan_txt, plan_txt_len);
    n2n_send_to_front(n2n_conn->n2n, n2n_conn->couple_id, plan_txt, plan_txt_len);
    if (local->key) {
        _FREE_IF(plan_txt);
    }
}

static void on_n2n_front_recv(n2n_t *n2n, int conn_id, const char *buf, ssize_t size) {
    _LOG("on_n2n_front_recv %d", conn_id);
    GET_LOCAL_INFO;
    send_to_back(local, n2n, n2n_conn->couple_id, buf, size);
}

static void on_n2n_backend_recv(n2n_t *n2n, int conn_id, const char *buf, ssize_t size) {
    _LOG("on_n2n_backend_recv %d", conn_id);
    GET_LOCAL_INFO;

    int rt = n2n_read_msg(buf, size, n2n_conn, on_read_n2n_msg);
    // _ERR("msg_read_len: %u", n2n_conn->msg_read_len);
    if (rt < 0) {
        // error
        _ERR("msg format error %d", conn_id);
        return;
    }
}

static void on_n2n_backend_connect(n2n_t *n2n, int conn_id) {
    _LOG("on_n2n_backend_connect %d", conn_id);
    GET_LOCAL_INFO;
    if (!send_to_back(local, n2n, conn_id, NULL, 0)) {
        n2n_close_conn(n2n, conn_id);
        return;
    }
    _LOG("on_n2n_backend_connect end %d", conn_id);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

local_server_t *init_local_server(uv_loop_t *loop, const char *listen_ip, uint16_t listen_port, const char *target_ip,
                                  uint16_t target_port, const char *pwd) {
    if (!loop || !listen_ip || listen_port <= 0 || !target_ip || target_port <= 0) {
        return NULL;
    }
    n2n_t *n2n = n2n_init_server(loop, listen_ip, listen_port, target_ip, target_port, on_n2n_front_accept,
                                 on_n2n_close, on_n2n_front_recv, on_n2n_backend_recv, on_n2n_backend_connect);
    if (!n2n) {
        return NULL;
    }
    local_server_t *local = (local_server_t *)_CALLOC(1, sizeof(local_server_t));
    _CHECK_OOM(local);
    n2n->data = local;
    local->loop = loop;
    local->n2n = n2n;

    if (pwd) {
        local->key = pwd2key(pwd);
        _LOG("start cipher mode %s", local->key);
    }

    return local;
}

void free_local_server(local_server_t *local) {
    if (!local) {
        return;
    }

    if (local->n2n) {
        n2n_free_server(local->n2n);  // TODO:
    }

    if (local->key) {
        _FREE_IF(local->key);
    }

    _FREE_IF(local);
}
