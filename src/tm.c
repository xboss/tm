#include "local_server.h"
#include "socks5_server.h"

#define DEFAULT_PORT 7000

int main() {
    uv_loop_t *loop = uv_default_loop();

    return uv_run(loop, UV_RUN_DEFAULT);
}
