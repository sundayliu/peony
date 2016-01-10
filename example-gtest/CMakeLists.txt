set(CMAKE_LEGACY_CYGWIN_WIN32 0)
cmake_minimum_required(VERSION 2.8)

option(test "Buld all tests." OFF)

project(FOO C CXX)

set(CMAKE_CXX_FLAGS "-g -Wall")

add_subdirectory(src)