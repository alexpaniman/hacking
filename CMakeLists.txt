cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

project(hacking VERSION 1.0)

set(   CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D _DEBUG -fno-stack-protector -no-pie -ggdb3 -std=c++20 -Wall -Wextra -Weffc++ -O0")
set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D _DEBUG -fno-stack-protector -no-pie -ggdb3 -std=c++20 -Wall -Wextra -Weffc++ -O0")

set(   CMAKE_CXX_FLAGS_RELEASE "-no-pie -fno-stack-protector -O0 -D NDEBUG -s")
set(CMAKE_LINKER_FLAGS_RELEASE "-no-pie -fno-stack-protector -O0 -D NDEBUG -s")

enable_language(ASM_FASM)

add_executable(hacking-bin hacking.cpp sha256.cpp printf-asm.s)

target_include_directories(
  hacking-bin PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR})
