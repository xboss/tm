CC = gcc
CFLAGS = -c -Wno-deprecated-declarations
# CFLAGS = -c -Wall
CDEBUG = -g -DDEBUG
# CDEBUG = -g 
SHARED = -fPIC --shared

OUTPUT_DIR = ./build/
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c, %.o, $(SRC))
OBJ_OUT = $(patsubst src/%.c, $(OUTPUT_DIR)%.o, $(SRC))
INCLUDE = -I./src -I./src/cJSON
LIB = -luv -lssl -lcrypto

CJSON_SRC = $(wildcard src/cJSON/*.c)
CJSON_OBJ = $(patsubst src/cJSON/%.c, %.o, $(CJSON_SRC))
CJSON_OBJ_OUT = $(patsubst src/cJSON/%.c, $(OUTPUT_DIR)%.o, $(CJSON_SRC))

# TEST_SRC = $(wildcard test/*.c)
# TEST_OBJ = $(patsubst test/%.c, %.o, $(TEST_SRC))

.PHONY:all clean test

all: $(OBJ)  $(CJSON_OBJ)
	$(CC) $(OBJ_OUT) $(CJSON_OBJ_OUT) -o $(OUTPUT_DIR)tm $(LIB)

%.o: src/%.c
	@echo $< $@
	$(CC) $(INCLUDE) $(CFLAGS) $(CDEBUG) $< -o $(OUTPUT_DIR)$@

%.o: ./src/cJSON/%.c
	@echo $< $@
	$(CC) $(INCLUDE) $(CFLAGS) $(CDEBUG) $< -o $(OUTPUT_DIR)$@
	
clean:
	rm -rf $(OUTPUT_DIR)*

lib:$(OBJ)  $(CJSON_OBJ)
	$(CC) $(SHARED) $(OBJ_OUT) $(CJSON_OBJ_OUT) -o $(OUTPUT_DIR)libtm.so $(LIB)

test:
	$(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/utils.c ./src/tcp.c  ./test/test_server.c -o $(OUTPUT_DIR)test_server 
	$(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/utils.c ./src/tcp.c ./test/test_client.c -o $(OUTPUT_DIR)test_client 
	$(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/utils.c ./src/cipher.c ./src/tcp.c ./src/n2n_server.c ./src/socks5_server.c  ./test/test_ss5.c -o $(OUTPUT_DIR)test_ss5
	$(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/utils.c ./src/cipher.c ./src/tcp.c ./src/n2n_server.c ./src/local_server.c ./test/test_local.c -o $(OUTPUT_DIR)test_local
	$(CC) $(INCLUDE) $(CDEBUG) $(LIB) ./src/utils.c ./src/cipher.c ./src/tcp.c  ./test/test.c -o $(OUTPUT_DIR)test
