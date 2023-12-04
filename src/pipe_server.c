// #include "pipe_server.h"

// #include "utils.h"
// #include "utlist.h"

// // #define MAX_PIPE_BUF_LEN 1024

// // typedef struct {
// //     char *blocks[MAX_PIPE_BUF_LEN];
// //     int blocks_cnt;
// // } pipe_buf_t;

// typedef struct {
//     char *buf;
//     pipe_buf_t *next, *prev;
// } pipe_buf_t;

// static void close_couple_conns(tcp_t *tcp, int conn_id) {
//     _LOG("close_couple_conns %d", conn_id);
//     IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
//     if (tcp_conn->couple_conn_id > 0) {
//         _LOG("close_couple_conns %d cp %d", conn_id, tcp_conn->couple_conn_id);
//         close_tcp_connection(tcp, tcp_conn->couple_conn_id);
//         tcp_conn->couple_conn_id = 0;
//     }
//     close_tcp_connection(tcp, conn_id);
// }

// static void on_front_accept(tcp_t *tcp, int conn_id) {
//     _LOG("on front accept %d", conn_id);
//     IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
//     pipe_t *pipe = (pipe_t *)tcp_conn->data;
//     assert(pipe);

//     // int *p_cid = (int *)_CALLOC(1, sizeof(int));
//     // *p_cid = conn_id;
//     // connect to backend
//     if (!connect_tcp_with_sockaddr(tcp, pipe->target_addr, (void *)conn_id)) {
//         // error
//         close_couple_conns(tcp, conn_id);
//     }
// }

// static void on_tcp_close(tcp_t *tcp, int conn_id) {
//     _LOG("on tcp close %d", conn_id);
//     // IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
//     // pipe_t *pipe = (pipe_t *)tcp_conn->data;
//     // assert(pipe);
//     close_couple_conns(tcp, conn_id);
// }

// static void on_tcp_recv(tcp_t *tcp, int conn_id, const char *buf, ssize_t size) {
//     _LOG("on tcp recv %d", conn_id);
//     IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
//     pipe_t *pipe = (pipe_t *)tcp_conn->data;
//     assert(pipe);

//     tcp_conn->couple_conn_id;
//     if (tcp_conn->couple_conn_id <= 0) {
//         // close_couple_conns(tcp, conn_id);
//         // maybe backend connection does not create
//         return;
//     }
//     IF_GET_TCP_CONN(couple_conn, tcp, tcp_conn->couple_conn_id, {
//         close_couple_conns(tcp, conn_id);
//         return;
//     });

//     // send to couple
//     // TODO:
// }
// static void on_back_connect(tcp_t *tcp, int conn_id) {
//     _LOG("back connect ok %d", conn_id);
//     IF_GET_TCP_CONN(tcp_conn, tcp, conn_id, { return; });
//     // pipe_t *pipe = (pipe_t *)tcp_conn->data;
//     // assert(pipe);
//     int cp_id = (int)tcp_conn->data;
//     if (cp_id <= 0) {
//         close_couple_conns(tcp, conn_id);
//         return;
//     }
//     IF_GET_TCP_CONN(couple_conn, tcp, cp_id, {
//         close_couple_conns(tcp, conn_id);
//         return;
//     });

//     tcp_conn->couple_conn_id = cp_id;
//     couple_conn->couple_conn_id = conn_id;
//     _LOG("back connect create couple %d %d", conn_id, cp_id);
// }

// pipe_t *init_pipe_server(uv_loop_t *loop, const char *listen_ip, uint16_t listen_port, const char *target_ip,
//                          uint16_t target_port) {
//     if (!loop || !listen_ip || listen_port <= 0 || !target_ip || target_port <= 0) {
//         return NULL;
//     }
//     tcp_t *tcp = init_tcp(loop, NULL, on_front_accept, on_back_connect, on_tcp_recv, on_tcp_close);
//     if (!tcp) {
//         return NULL;
//     }

//     struct sockaddr_in listen_sockaddr;
//     int r = uv_ip4_addr(listen_ip, listen_port, &listen_sockaddr);
//     IF_UV_ERROR(r, "listen ipv4 addr error", { return false; });

//     struct sockaddr_in target_sockaddr;
//     int r = uv_ip4_addr(target_ip, target_port, &target_sockaddr);
//     IF_UV_ERROR(r, "listen ipv4 addr error", { return false; });

//     bool rt = start_tcp_server_with_sockaddr(tcp, listen_sockaddr);
//     if (!rt) {
//         free_tcp(tcp);
//         return NULL;
//     }
//     pipe_t *pipe = (pipe_t *)_CALLOC(1, sizeof(pipe_t));
//     _CHECK_OOM(pipe);
//     tcp->data = pipe;
//     pipe->loop = loop;
//     pipe->tcp = tcp;
//     pipe->listen_addr = listen_sockaddr;
//     pipe->target_addr = target_sockaddr;
//     return pipe;
// }

// void free_pipe_server(pipe_t *pipe) {
//     if (!pipe) {
//         return;
//     }

//     if (pipe->tcp) {
//         stop_tcp_server(pipe->tcp);
//         free_tcp(pipe->tcp);
//     }

//     free(pipe);
// }
