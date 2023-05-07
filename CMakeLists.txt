cmake_minimum_required(VERSION 2.8.12)
project(execore)
set(CMAKE_C_STANDARD 11)

set(SOURCES
        src/execore.c
        src/execore_maps.c
        src/execore_maps.h
        src/execore_mman.h
        src/execore_procfs.h
        src/execore_ptrace.h
        src/execore_stdlib.h
        src/execore_string.h
        src/execore_unistd.c
        src/execore_unistd.h
        src/execore_user.h
        src/stdint.h
)
add_executable(execore ${SOURCES})
target_compile_options(execore PRIVATE
        -fno-asynchronous-unwind-tables
        -fno-ident
        -fno-stack-protector
        -Wall
        -Wextra
        -Werror
)
target_include_directories(execore PRIVATE src src/nolibc)
target_link_options(execore PRIVATE
        -nostdlib
        -static
)
target_link_libraries(execore gcc)

add_custom_target(fmt
        COMMAND clang-format -i ${SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

set(NOLIBC_SVN_URL
        https://github.com/torvalds/linux/tags/v6.3/tools/include/nolibc)
add_custom_target(nolibc
        COMMAND rm -rf src/nolibc && svn export ${NOLIBC_SVN_URL} src/nolibc
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
