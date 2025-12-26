cmake_minimum_required(VERSION 3.10)
project(bfd LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_library(bfd_core
    src/bfd_session.c
    src/bfd_engine.c
    src/bfd_cli.c
)

target_link_libraries(bfd_core m)

add_executable(bfd_initiator initiator/main.c)
target_link_libraries(bfd_initiator bfd_core)

add_executable(bfd_responder responder/main.c)
target_link_libraries(bfd_responder bfd_core)

add_executable(bfdctl cli/bfdctl.c)
target_link_libraries(bfdctl bfd_core)
