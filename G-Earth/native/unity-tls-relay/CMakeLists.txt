cmake_minimum_required(VERSION 3.25)
cmake_policy(SET CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
project(unity_tls_relay C)

include(FetchContent)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(MSVC_STATIC_RUNTIME ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG c765c831e5c2a0971410692f92f7a81d6ec65ec2
    GIT_SUBMODULES framework)
FetchContent_MakeAvailable(mbedtls)

add_executable(unity_tls_relay unity_tls_relay.c)
if(MSVC)
    target_compile_options(unity_tls_relay PRIVATE /W4 /WX)
endif()
target_link_libraries(
    unity_tls_relay
    PRIVATE
    MbedTLS::mbedtls
    MbedTLS::mbedx509
    MbedTLS::mbedcrypto
    crypt32
    ws2_32
    bcrypt)
