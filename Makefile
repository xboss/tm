CC = gcc
CFLAGS = -c -Wall
CDEBUG = -g -DDEBUG
# CDEBUG = -g 
OUTPUT_DIR = ./build/
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c, %.o, $(SRC))
OBJ_OUT = $(patsubst src/%.c, $(OUTPUT_DIR)%.o, $(SRC))
INCLUDE = -I./src
LIB = -luv -lssl -lcrypto

# TEST_SRC = $(wildcard test/*.c)
# TEST_OBJ = $(patsubst test/%.c, %.o, $(TEST_SRC))

.PHONY:all clean test

all: $(OBJ)
	$(CC) $(OBJ_OUT) -o $(OUTPUT_DIR)tm $(LIB)

%.o: src/%.c
	@echo $< $@
	$(CC) $(INCLUDE) $(CFLAGS) $(CDEBUG) $< -o $(OUTPUT_DIR)$@

clean:
	rm -rf $(OUTPUT_DIR)*

# $(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/tcp_server.c -o $(OUTPUT_DIR)tcp_server 
# $(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/tcp_server.c ./src/socks5_server.c -o $(OUTPUT_DIR)socks5_server 
# $(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/tcp_connection.c -o $(OUTPUT_DIR)tcp_connection 
test:
	$(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/tcp_connection.c ./src/tcp_server.c ./test/test_server.c -o $(OUTPUT_DIR)test_server 
	$(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/tcp_connection.c ./test/test_client.c -o $(OUTPUT_DIR)test_client 
	$(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/tcp_connection.c ./src/tcp_server.c ./src/socks5_server.c ./test/test_ss5.c -o $(OUTPUT_DIR)test_ss5