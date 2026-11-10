cmake_minimum_required(VERSION 3.16)

project(SSRF_Target_Server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ssrf_target
    src/main.cpp
    src/server.cpp
    src/ssrf_handler.cpp
    src/internal_service.cpp
    src/internal_server.cpp
    src/callback_record.cpp
    src/callback_server.cpp
)

target_include_directories(ssrf_target PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(ssrf_target PRIVATE ws2_32)
endif()

if(MSVC)
    target_compile_options(ssrf_target PRIVATE /W4)
else()
    target_compile_options(ssrf_target PRIVATE -Wall -Wextra)
endif()
