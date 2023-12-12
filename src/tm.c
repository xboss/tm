#include "cipher.h"
#include "local_server.h"
#include "socks5_server.h"
#include "utils.h"

typedef struct {
    int mode;
    char listen_ip[TCP_MAX_IP_LEN + 1];
    uint16_t listen_port;
    char remote_ip[TCP_MAX_IP_LEN + 1];
    uint16_t remote_port;
    char password[CIPHER_KEY_LEN + 1];
} tm_config_t;

static tm_config_t config;

#define PRT_USAGE(_e_msg)                                                                    \
    _ERR("error: %s", _e_msg);                                                               \
    _ERR("Usage: tm <mode> <password> <listen ip> <listen port> [remote ip] [remote port]"); \
    _ERR("        <mode>: local or socks5")

static int parse_args(int argc, char const *argv[]) {
    if (argc < 4 || !argv[1] || !argv[2] || !argv[3] || !argv[4]) {
        PRT_USAGE("invalid parameter");
        return -1;
    }
    config.mode = 0;
    if (strcmp(argv[1], "local") == 0) {
        config.mode = 1;
    }
    if (strcmp(argv[1], "socks5") == 0) {
        config.mode = 2;
    }
    if (config.mode == 0) {
        PRT_USAGE("mode error, only supports local and sock5 modes");
        return -1;
    }

    int len = strnlen(argv[2], CIPHER_KEY_LEN + 1);
    len = len > CIPHER_KEY_LEN ? CIPHER_KEY_LEN : len;
    memcpy(config.password, argv[2], len);

    len = strnlen(argv[3], TCP_MAX_IP_LEN + 1);
    if (len > TCP_MAX_IP_LEN) {
        PRT_USAGE("invalid listen ip");
        return -1;
    }
    memcpy(config.listen_ip, argv[3], len);
    config.listen_port = (uint16_t)atoi(argv[4]);

    if (config.mode == 1) {
        // local mode
        if (!argv[5] || !argv[6]) {
            PRT_USAGE("invalid remote ip or port");
            return -1;
        }
        len = strnlen(argv[5], TCP_MAX_IP_LEN + 1);
        if (len > TCP_MAX_IP_LEN) {
            PRT_USAGE("invalid remote ip");
            return -1;
        }
        memcpy(config.remote_ip, argv[5], len);
        config.remote_port = (uint16_t)atoi(argv[6]);
    }

    return 0;
}

void signal_handler(uv_signal_t *handle, int signum) {
    _LOG("signal %d", signum);
    if (SIGPIPE == signum) {
        return;
    }
    if (SIGINT == signum) {
        uv_stop(handle->loop);
        _LOG("stop loop");
    }

    // uv_signal_stop(handle);
    // _FREE_IF(handle);
    _LOG("stop signal %d", signum);
}

static bool init_signal(uv_loop_t *loop, uv_signal_t *sig, int signum) {
    int r = uv_signal_init(loop, sig);
    IF_UV_ERROR(r, "uv signal init", { return false; });
    r = uv_signal_start(sig, signal_handler, signum);
    IF_UV_ERROR(r, "uv signal start", { return false; });
    return true;
}

int main(int argc, char const *argv[]) {
    uv_loop_t *loop = uv_default_loop();

    bzero(&config, sizeof(tm_config_t));
    if (parse_args(argc, argv) != 0) {
        return 1;
    }

    _LOG("mode: %d pwd:%s listen ip: %s listen port: %u remote ip: %s remote port: %u", config.mode, config.password,
         config.listen_ip, config.listen_port, config.remote_ip, config.remote_port);

    local_server_t *local = NULL;
    socks5_server_t *socks5 = NULL;

    if (config.mode == 1) {
        // local server
        local = init_local_server(loop, config.listen_ip, config.listen_port, config.remote_ip, config.remote_port,
                                  config.password);
        if (!local) {
            _ERR("local server start error");
            return 1;
        }

    } else if (config.mode == 2) {
        // socks5 server
        socks5 = init_socks5_server(loop, config.listen_ip, config.listen_port, config.password);
        if (!socks5) {
            _ERR("socks5 server start error");
            return 1;
        }
    } else {
        _ERR("error mode");
        return 1;
    }

    // uv_signal_t *sig_pipe = (uv_signal_t *)_CALLOC(1, sizeof(uv_signal_t));
    // _CHECK_OOM(sig_pipe);
    // if (!init_signal(loop, sig_pipe, SIGPIPE)) {
    //     _ERR("init signal error");
    //     _FREE_IF(sig_pipe);
    //     return 1;
    // }

    // uv_signal_t *sig_int = (uv_signal_t *)_CALLOC(1, sizeof(uv_signal_t));
    // _CHECK_OOM(sig_int);
    // if (!init_signal(loop, sig_int, SIGINT)) {
    //     _ERR("init signal error");
    //     _FREE_IF(sig_int);
    //     return 1;
    // }

    uv_signal_t *sig = (uv_signal_t *)_CALLOC(1, sizeof(uv_signal_t));
    _CHECK_OOM(sig);
    if (!init_signal(loop, sig, SIGPIPE) || !init_signal(loop, sig, SIGINT)) {
        _ERR("init signal error");
        _FREE_IF(sig);
        return 1;
    }

    int rt = uv_run(loop, UV_RUN_DEFAULT);
    if (local) {
        free_local_server(local);
    }
    if (socks5) {
        free_socks5_server(socks5);
    }
    // _FREE_IF(sig_pipe);
    _FREE_IF(sig);
    // uv_loop_close(loop);
    _LOG("tm end");

    return rt;
}
