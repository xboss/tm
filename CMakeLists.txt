cmake_minimum_required(VERSION 3.20.0)
project(tm VERSION 0.1.0)


SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wno-deprecated-declarations -DDEBUG -ggdb")
# SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb ")
SET(CMAKE_C_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

message("project dir: ${PROJECT_SOURCE_DIR} compiler: ${CMAKE_C_COMPILER_ID}")

link_directories("/usr/local/lib")

include_directories(${PROJECT_SOURCE_DIR}/src/)
include_directories(${PROJECT_SOURCE_DIR}/src/cJSON)

aux_source_directory(${PROJECT_SOURCE_DIR}/src DIR_SRCS)
aux_source_directory(${PROJECT_SOURCE_DIR}/src/cJSON DIR_SRCS_CJSON)

# ############# main #############
add_executable(tm ${DIR_SRCS} ${DIR_SRCS_CJSON})
target_link_libraries(tm ssl)
target_link_libraries(tm crypto)
target_link_libraries(tm uv)

# ############# static #############
# add_executable(tm ${DIR_SRCS} ${DIR_SRCS_CJSON})
# target_link_libraries(tm_static ssl -static)
# target_link_libraries(tm_static crypto -static)
# target_link_libraries(tm_static uv -static)

# ############# sharded lib #############
# list(REMOVE_ITEM DIR_SRCS ${PROJECT_SOURCE_DIR}/src/tm.c)
# add_library(libtm SHARED ${DIR_SRCS} ${DIR_SRCS_CJSON})
# target_link_libraries(libtm ssl)
# target_link_libraries(libtm crypto)
# target_link_libraries(libtm uv)
