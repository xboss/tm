#ifndef _LOCAL_SERVER_H
#define _LOCAL_SERVER_H

#include "n2n_server.h"

typedef struct local_server_s local_server_t;

local_server_t *init_local_server(uv_loop_t *loop, const char *listen_ip, uint16_t listen_port, const char *target_ip,
                                  uint16_t target_port);
void free_local_server(local_server_t *local);

#endif  // LOCAL_SERVER_H