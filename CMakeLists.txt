cmake_minimum_required(VERSION 3.20)
project(Zoom)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(minhook STATIC
    minhook/src/buffer.c
    minhook/src/hook.c
    minhook/src/trampoline.c
    minhook/src/hde/hde32.c
    minhook/src/hde/hde64.c
)
target_include_directories(minhook PUBLIC minhook/include)

add_library(${PROJECT_NAME} SHARED src/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE minhook)
target_compile_definitions(${PROJECT_NAME} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
