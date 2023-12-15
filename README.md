# TM
Maybe it doesn't deserve a name.

## Features
* Socks5
* Security
* Tunnel

## Supported platforms
Linux, MacOS, Windows

## Building
* Dependencies
  * [libuv-v1.47](https://dist.libuv.org/dist/v1.47.0/)
  * [openssl](https://github.com/openssl/openssl/blob/master/INSTALL.md#installing-openssl)

* Compile
```
$ cd tm
$ mkdir build
$ make
```
## Configuration file
The configuration file is in JSON format.

### Items
* "mode"
  * Required
  * "socks5_server" means starting the socks5 server.
  * "local_server" means starting the local server.
* "listen_ip" and "listen_port"
  * Required
  * The IP and port used for listening.
* "password"
  * Required
  * The password used to encrypt data in transmission.
* "remote_ip" and "remote_port"
  * Required in "local_server" mode
  * The IP and port of remote socks5 server.
* "socks5_auth_mode"
  * Required in "socks5_server" mode
  * The authentication mode of socks5, where 0 indicates no authentication, and 1 indicates authentication through username and password.
* "socks5_users"
  * Required when using the "socks5_server" mode and the username and password authentication method.
  * It is a array. Each of them contains a "name" and "password".


## Usage

* Start remote socks5 service
```
$ tm tm_socks5_server.conf
```

* Start local service
```
$ tm tm_local_server.conf
```
