cmake_minimum_required(VERSION 3.26)
project(pqchat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories("../liboqs/build/include")
link_directories("../liboqs/build/lib")

add_executable(pqchat main.cpp)
target_link_libraries(pqchat oqs crypto)
