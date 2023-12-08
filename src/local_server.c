#include "local_server.h"

#include "utils.h"

struct local_server_s {
    uv_loop_t *loop;
    n2n_t *n2n;
};

/* -------------------------------------------------------------------------- */
/*                                  callback                                  */
/* -------------------------------------------------------------------------- */

#define GET_LOCAL_INFO                                   \
    local_server_t *local = (local_server_t *)n2n->data; \
    assert(local);                                       \
    IF_GET_N2N_CONN(n2n_conn, n2n, conn_id, {});         \
    assert(n2n_conn)

void on_n2n_front_accept(n2n_t *n2n, int conn_id) {
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

void on_n2n_close(n2n_t *n2n, int conn_id) {
    _LOG("on_n2n_close %d", conn_id);
    // GET_LOCAL_INFO;
    // n2n_conn->data = NULL;
    // free_ss5_conn(ss5_conn);
}

void on_n2n_front_recv(n2n_t *n2n, int conn_id, const char *buf, ssize_t size) {
    _LOG("on_n2n_front_recv %d", conn_id);
    GET_LOCAL_INFO;
    n2n_send_to_back(n2n, n2n_conn->couple_id, buf, size);
}

void on_n2n_backend_recv(n2n_t *n2n, int conn_id, const char *buf, ssize_t size) {
    _LOG("on_n2n_backend_recv %d", conn_id);
    GET_LOCAL_INFO;
    n2n_send_to_front(n2n, n2n_conn->couple_id, buf, size);
}

void on_n2n_backend_connect(n2n_t *n2n, int conn_id) {
    _LOG("on_n2n_backend_connect %d", conn_id);
    GET_LOCAL_INFO;
    if (!n2n_send_to_back(n2n, conn_id, NULL, 0)) {
        n2n_close_conn(n2n, conn_id);
        return;
    }
    _LOG("on_n2n_backend_connect end %d", conn_id);
}

/* -------------------------------------------------------------------------- */
/*                                   public                                   */
/* -------------------------------------------------------------------------- */

local_server_t *init_local_server(uv_loop_t *loop, const char *listen_ip, uint16_t listen_port, const char *target_ip,
                                  uint16_t target_port) {
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
    return local;
}

void free_local_server(local_server_t *local) {
    if (!local) {
        return;
    }

    if (local->n2n) {
        n2n_free_server(local->n2n);  // TODO:
    }

    free(local);
}
