#include "cJSON.h"
#include "cipher.h"
#include "local_server.h"
#include "socks5_server.h"
#include "utils.h"

/* -------------------------------------------------------------------------- */
/*                                   config                                   */
/* -------------------------------------------------------------------------- */

#define MAX_SOCKS_USER_NM_SZ 32
#define MAX_SOCKS_USER_PWD_SZ 32

typedef struct {
    char name[MAX_SOCKS_USER_NM_SZ + 1];
    char pwd[MAX_SOCKS_USER_PWD_SZ + 1];
    UT_hash_handle hh;
} socks5_user_t;

typedef struct {
    int mode;  // 1: local server; 2: socks5 server
    char listen_ip[TCP_MAX_IP_LEN + 1];
    uint16_t listen_port;
    char remote_ip[TCP_MAX_IP_LEN + 1];
    uint16_t remote_port;
    char pwd[CIPHER_KEY_LEN + 1];
    int socks5_auth_mode;  // 0:no auth; 1:username/password
    socks5_user_t *users;
} tm_config_t;

#define LOAD_CONF_ERROR(_reason)                       \
    _ERR("config file parsing failed: %s\n", _reason); \
    cJSON_Delete(m_json);                              \
    return false

#define CHK_CONF_STR(_obj, _key, _emsg)                    \
    js_obj = cJSON_GetObjectItemCaseSensitive(_obj, _key); \
    if (!js_obj || !cJSON_IsString(js_obj)) {              \
        LOAD_CONF_ERROR(_emsg);                            \
    }

#define CHK_CONF_INT(_obj, _key, _emsg)                                \
    js_obj = cJSON_GetObjectItemCaseSensitive(_obj, _key);             \
    if (!js_obj || !cJSON_IsNumber(js_obj) || js_obj->valueint <= 0) { \
        LOAD_CONF_ERROR(_emsg);                                        \
    }

static bool load_config(const char *filename, tm_config_t *config) {
    char *json_str = load_str_file(filename);
    if (json_str == NULL) {
        return false;
    }
    cJSON *m_json = cJSON_Parse(json_str);
    _FREE_IF(json_str);
    if (m_json == NULL) {
        _ERR("config file parse error");
        return false;
    }
    if (!cJSON_IsObject(m_json)) {
        LOAD_CONF_ERROR("json format error");
    }
    const char val_mode_local[] = "local_server";
    const char val_mode_socks5[] = "socks5_server";
    const char *nm_mode = "mode";
    const char *nm_pwd = "password";
    const char *nm_listen_ip = "listen_ip";
    const char *nm_listen_port = "listen_port";
    const char *nm_remote_ip = "remote_ip";
    const char *nm_remote_port = "remote_port";
    const char *nm_socks5_auth_mode = "socks5_auth_mode";
    const char *nm_socks5_users = "socks5_users";
    const char *nm_socks5_user_name = "name";
    const char *nm_socks5_user_pwd = "password";

    size_t v_len = 0;
    cJSON *js_obj = NULL;
    // mode
    CHK_CONF_STR(m_json, nm_mode, "invalid field 'mode'");
    if (strncasecmp(js_obj->valuestring, val_mode_local, sizeof(val_mode_local)) == 0) {
        config->mode = 1;
    } else if (strncasecmp(js_obj->valuestring, val_mode_socks5, sizeof(val_mode_socks5)) == 0) {
        config->mode = 2;
    } else {
        LOAD_CONF_ERROR("invalid field 'mode'");
    }
    // password
    CHK_CONF_STR(m_json, nm_pwd, "invalid field 'password'");
    v_len = strnlen(js_obj->valuestring, CIPHER_KEY_LEN + 1);
    v_len = v_len > CIPHER_KEY_LEN ? CIPHER_KEY_LEN : CIPHER_KEY_LEN;
    memcpy(config->pwd, js_obj->valuestring, v_len);
    // listen_ip
    CHK_CONF_STR(m_json, nm_listen_ip, "invalid field 'listen_ip'");
    v_len = strnlen(js_obj->valuestring, TCP_MAX_IP_LEN + 1);
    if (v_len > TCP_MAX_IP_LEN) {
        LOAD_CONF_ERROR("invalid field 'listen_ip'");
    }
    memcpy(config->listen_ip, js_obj->valuestring, v_len);
    // listen_port
    CHK_CONF_INT(m_json, nm_listen_port, "invalid field 'listen_port'");
    config->listen_port = (uint16_t)js_obj->valueint;

    if (config->mode == 1) {
        // remote_ip
        CHK_CONF_STR(m_json, nm_remote_ip, "invalid field 'remote_ip'");
        v_len = strnlen(js_obj->valuestring, TCP_MAX_IP_LEN + 1);
        if (v_len > TCP_MAX_IP_LEN) {
            LOAD_CONF_ERROR("invalid field 'remote_ip'");
        }
        memcpy(config->remote_ip, js_obj->valuestring, v_len);
        // remote_port
        CHK_CONF_INT(m_json, nm_remote_port, "invalid field 'remote_port'");
        config->remote_port = (uint16_t)js_obj->valueint;
    }

    if (config->mode == 2) {
        // socks5_auth_mode
        config->socks5_auth_mode = 0;
        js_obj = cJSON_GetObjectItemCaseSensitive(m_json, nm_socks5_auth_mode);
        if (js_obj && cJSON_IsNumber(js_obj) && js_obj->valueint == 1) {
            config->socks5_auth_mode = 1;
            // users
            cJSON *js_users_arr = cJSON_GetObjectItemCaseSensitive(m_json, nm_socks5_users);
            if (!js_users_arr || !cJSON_IsArray(js_users_arr)) {
                LOAD_CONF_ERROR("invalid field 'socks5_users'");
            }
            cJSON *el_user = NULL;
            // char name[MAX_SOCKS_USER_NM_SZ + 1];
            // char pwd[MAX_SOCKS_USER_PWD_SZ + 1];
            cJSON_ArrayForEach(el_user, js_users_arr) {
                // bzero(name, sizeof(name));
                // bzero(pwd, sizeof(pwd));
                if (!cJSON_IsObject(el_user)) {
                    LOAD_CONF_ERROR("invalid field 'socks5_users'");
                }
                // name
                CHK_CONF_STR(el_user, nm_socks5_user_name, "invalid field 'socks5_users.name'");
                v_len = strnlen(js_obj->valuestring, MAX_SOCKS_USER_NM_SZ + 1);
                if (v_len > MAX_SOCKS_USER_NM_SZ) {
                    _ERR("length must be less than %d, name: %s", MAX_SOCKS_USER_NM_SZ, js_obj->valuestring);
                    LOAD_CONF_ERROR("invalid length field 'socks5_users.name'");
                }
                socks5_user_t *user = _CALLOC(1, sizeof(socks5_user_t));
                _CHECK_OOM(user);
                memcpy(user->name, js_obj->valuestring, v_len);
                // password
                CHK_CONF_STR(el_user, nm_socks5_user_pwd, "invalid field 'socks5_users.password'");
                v_len = strnlen(js_obj->valuestring, MAX_SOCKS_USER_PWD_SZ + 1);
                if (v_len > MAX_SOCKS_USER_PWD_SZ) {
                    _ERR("length must be less than %d, password: %s", MAX_SOCKS_USER_PWD_SZ, js_obj->valuestring);
                    _FREE_IF(user);
                    LOAD_CONF_ERROR("invalid length field 'socks5_users.password'");
                }
                memcpy(user->pwd, js_obj->valuestring, v_len);
                HASH_ADD_STR(config->users, name, user);
            }
        }
    }

    cJSON_Delete(m_json);
    return true;
}

/* -------------------------------------------------------------------------- */
/*                                     TM                                     */
/* -------------------------------------------------------------------------- */

#define PRT_USAGE(_e_msg) \
    _ERR("%s", _e_msg);   \
    printf("Usage: tm <configfile>\n");

static tm_config_t config;

static void signal_handler(uv_signal_t *handle, int signum) {
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

static int on_auth_socks5_user(const char *name, int name_len, const char *pwd, int pwd_len) {
    if (!name || !pwd) {
        return -1;
    }
    if (name_len > MAX_SOCKS_USER_NM_SZ) {
        return -1;
    }

    char name_str[MAX_SOCKS_USER_NM_SZ + 1] = {0};
    memcpy(name_str, name, name_len);
    socks5_user_t *user = NULL;
    HASH_FIND_STR(config.users, name_str, user);
    if (!user) return -1;
    int pwd_len_tb = strlen(user->pwd);
    if (pwd_len != pwd_len_tb) return -1;

    for (int i = 0; i < pwd_len_tb; i++) {
        if (user->pwd[i] != pwd[i]) {
            return -1;
        }
    }
    return 0;
}

int main(int argc, char const *argv[]) {
    uv_loop_t *loop = uv_default_loop();
    // bzero(&config, sizeof(tm_config_t));
    memset(&config, 0, sizeof(tm_config_t));

    if (argc < 2 || !argv[1]) {
        PRT_USAGE("invalid parameter");
        return 1;
    }

    if (!load_config(argv[1], &config)) {
        return 1;
    }

    _LOG("mode: %d pwd:%s listen ip: %s listen port: %u remote ip: %s remote port: %u socks5_auth_mode: %d",
         config.mode, config.pwd, config.listen_ip, config.listen_port, config.remote_ip, config.remote_port,
         config.socks5_auth_mode);

    local_server_t *local = NULL;
    socks5_server_t *socks5 = NULL;

    if (config.mode == 1) {
        // local server
        local = init_local_server(loop, config.listen_ip, config.listen_port, config.remote_ip, config.remote_port,
                                  config.pwd);
        if (!local) {
            _ERR("local server start error");
            return 1;
        }

    } else if (config.mode == 2) {
        // socks5 server
        socks5 = init_socks5_server(loop, config.listen_ip, config.listen_port, config.pwd, config.socks5_auth_mode,
                                    on_auth_socks5_user);
        if (!socks5) {
            _ERR("socks5 server start error");
            return 1;
        }
    } else {
        _ERR("error mode");
        return 1;
    }

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
    _FREE_IF(sig);
    // uv_loop_close(loop);
    _LOG("tm end");

    return rt;
}

// int main(int argc, char const *argv[]) {
//     // TODO:  test
//     bzero(&config, sizeof(tm_config_t));
//     bool rt = load_config("./test/tm.conf", &config);
//     assert(rt);
//     return 0;
// }