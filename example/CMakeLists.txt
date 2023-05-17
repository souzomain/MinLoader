cmake_minimum_required(VERSION 3.0)
set(CMAKE_SYSTEM_NAME "Windows")
set(CMAKE_C_COMPILER "x86_64-w64-mingw32-gcc")

project(memload C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static -static-libgcc -Os -Wno-write-strings -fomit-frame-pointer -fno-exceptions -fmerge-all-constants -fdata-sections -ffunction-sections")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set( 
    SRC 
    memload.c
    ../loader.c
    ../winapi.c
    ../ministd.c
)

add_executable(${PROJECT_NAME} ${SRC})
add_executable(test test.c)
