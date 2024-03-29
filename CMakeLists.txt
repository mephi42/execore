cmake_minimum_required(VERSION 2.8.12)
cmake_policy(SET CMP0048 NEW)
project(execore
        VERSION 0.1
        LANGUAGES C
)
set(CMAKE_C_STANDARD 11)

#
# Main.
#

set(SOURCES
        src/execore.c
        src/execore.h
        src/execore_elf.c
        src/execore_elf.h
        src/execore_maps.c
        src/execore_maps.h
        src/execore_mman.h
        src/execore_procfs.h
        src/execore_ptrace.h
        src/execore_stdlib.c
        src/execore_stdlib.h
        src/execore_string.h
        src/execore_unistd.c
        src/execore_unistd.h
        src/execore_user.h
        src/fakelibc/stdint.h
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
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  target_compile_options(execore PRIVATE -Wno-unknown-attributes)
endif()
target_include_directories(execore PRIVATE src src/fakelibc src/nolibc)
set(LDS_S ${CMAKE_SOURCE_DIR}/src/execore.lds.S)
set(LDS ${CMAKE_BINARY_DIR}/execore.lds)
add_custom_command(OUTPUT ${LDS}
	MAIN_DEPENDENCY ${LDS_S}
        COMMAND ${CMAKE_C_COMPILER} -E ${LDS_S} -P -o ${LDS}
)
add_custom_target(preprocess_lds DEPENDS ${LDS})

target_link_options(execore PRIVATE
        -nostdlib
        -static
        -Wl,--build-id=none
        -Wl,--script=${LDS}
)
set_target_properties(execore PROPERTIES LINK_DEPENDS ${LDS})
add_dependencies(execore preprocess_lds)
target_link_libraries(execore gcc)

#
# Testing.
#

enable_testing()

set(TEST_SOURCES
        test/execore_maps.c
        test/execore_stdlib.c
        test/execore_unistd.c
        test/nolibc.h
        test/test.c
        test/test.h
        test/test_execvpe.c
        test/test_maps.c
)

function(add_test_config SUFFIX CFLAGS LDFLAGS)
  add_executable(test_execore${SUFFIX} ${TEST_SOURCES})
  target_compile_definitions(test_execore${SUFFIX} PRIVATE
          -DCMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
  )
  target_compile_options(test_execore${SUFFIX} PRIVATE ${CFLAGS})
  target_include_directories(test_execore${SUFFIX} PRIVATE test src)
  target_link_options(test_execore${SUFFIX} PRIVATE ${LDFLAGS})
  add_test(NAME test_execore${SUFFIX} COMMAND test_execore${SUFFIX})
endfunction()

add_test_config("" "" "")
add_test_config(_asan -fsanitize=address -fsanitize=address)
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
  add_test_config(_msan -fsanitize=memory -fsanitize=memory)
endif()
add_test_config(_ubsan -fsanitize=undefined -fsanitize=undefined)

add_executable(phoenix test/phoenix.c)
add_test(
        NAME phoenix
        COMMAND test/phoenix.test $<TARGET_FILE:execore> $<TARGET_FILE:phoenix>
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_test(
        NAME clang-format
        COMMAND clang-format --dry-run -Werror ${SOURCES} ${TEST_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

set(PYTHON_SOURCES scripts/execore-record.py)

add_test(
        NAME flake8
        COMMAND flake8 --max-line-length=88 ${PYTHON_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_test(
        NAME black
        COMMAND black --check ${PYTHON_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

set(PHOENIX_TESTS
        test/phoenix.test
        test/record+replay-crash.test
        test/record-replay-crash.test
        test/record-replay-fgmemory.test
        test/record-replay-memory.test
        test/record-replay-remote-fgmemory.test
        test/record-replay-remote-memory.test
        test/record-replay-remote.test
        test/record-replay-remote-chroot.test
        test/record+replay.test
        test/record-replay.test
)

set(SHELL_SOURCES
        scripts/execore-replay
        test/phoenix-common.sh
        test/test_execvpe.sh
        ${PHOENIX_TESTS}
)

add_test(
        NAME shellcheck
        COMMAND shellcheck --source-path=test ${SHELL_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_test(
        NAME shfmt
        COMMAND shfmt -d -i 4 ${SHELL_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

foreach(test ${PHOENIX_TESTS})
  get_filename_component(test_name ${test} NAME)
  add_test(
          NAME ${test_name}
          COMMAND ${test} $<TARGET_FILE:execore> $<TARGET_FILE:phoenix>
          WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  )
endforeach()

#
# Maintenance.
#

add_custom_target(fmt
        COMMAND clang-format -i ${SOURCES} ${TEST_SOURCES} &&
                black ${PYTHON_SOURCES} &&
                shfmt -w -i 4 ${SHELL_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

set(NOLIBC_SVN_URL
        https://github.com/torvalds/linux/tags/v6.6/tools/include/nolibc)
add_custom_target(nolibc
        COMMAND rm -rf src/nolibc && svn export ${NOLIBC_SVN_URL} src/nolibc
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
