# tm
Maybe it doesn't deserve a name.

## Features
* Socks5
* Security
* Tunnel

## Building
* Dependencies
  * [libuv-v1.47](https://dist.libuv.org/dist/v1.47.0/)
  * [openssl](https://github.com/openssl/openssl/blob/master/INSTALL.md#installing-openssl)
* compile
```
cd tm
mkdir build
make
```

## Usage
* Help
```
tm 
Usage: tm <mode> <password> <listen ip> <listen port> [remote ip] [remote port]
        <mode>: local or socks5
```

* Start remote socks5 service
```
tm socks5 yourpassword 0.0.0.0 2222
```

* Start local service
```
tm local yourpassword 0.0.0.0 1111 127.0.0.1 2222
```
