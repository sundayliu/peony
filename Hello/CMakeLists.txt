PROJECT(HELLO C CXX)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH ${HELLO_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
add_subdirectory(src)