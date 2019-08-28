cmake_minimum_required(VERSION 3.14)
project(Mine)

set(CMAKE_CXX_STANDARD 17)

add_executable(Mine main.cpp)
target_link_libraries(Mine gcrypt)
