// #ifndef _PIPE_SERVER_H
// #define _PIPE_SERVER_H

// #include <stdbool.h>
// #include <uv.h>

// #include "tcp.h"
// #include "uthash.h"

// // typedef struct {
// //     int conn_id;
// //     int cp_id;
// //     // int cp_id[2];  // cp_id[0]:from_id, cp_id:to_id
// //     UT_hash_handle hh;
// // } couple_t;

// typedef struct {
//     uv_loop_t *loop;
//     tcp_t *tcp;
//     struct sockaddr_in listen_addr;
//     struct sockaddr_in target_addr;
//     // uint16_t listen_port;
//     // target_addr;
//     // uint16_t target_port;
//     // couple_t *cp_set;
// } pipe_t;

// pipe_t *init_pipe_server(uv_loop_t *loop, const char *listen_ip, uint16_t listen_port, const char *target_ip,
//                          uint16_t target_port);
// void free_pipe_server(pipe_t *pipe);

// #endif  // PIPE_SERVER_H