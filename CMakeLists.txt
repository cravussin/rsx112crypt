cmake_minimum_required(VERSION 3.7)
project(tp_chiffrement)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c aes.c)
add_executable(rsx112crypt ${SOURCE_FILES})