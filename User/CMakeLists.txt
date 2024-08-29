cmake_minimum_required(VERSION 2.6)
project(kernel_connect)

target_include_directories(kernel_connect PUBLIC "include")
file(SOURCES GLOB_RECURSE "src/*.cpp")

add_executable(kernel_connect ${SOURCES})
target_link_libraries(kernel_connect PUBLIC -pthread)
