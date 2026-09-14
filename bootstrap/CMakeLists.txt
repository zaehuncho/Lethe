cmake_minimum_required(VERSION 3.20)
project(LetheShardBootstrap C)

set(CMAKE_C_STANDARD 11)

include(CTest)

add_library(LetheKR2Protocol STATIC
    key_release_protocol.c
)
target_include_directories(LetheKR2Protocol PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(LetheKR2Crypto STATIC
    key_release_crypto.c
)
target_include_directories(LetheKR2Crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(LetheKR2Crypto PUBLIC
    LetheKR2Protocol
    bcrypt
)

add_executable(LetheShardBootstrap WIN32 shard_bootstrap.c)

target_link_libraries(LetheShardBootstrap PRIVATE
    kernel32
    bcrypt
    winhttp
    advapi32
    shlwapi
)

target_compile_definitions(LetheShardBootstrap PRIVATE
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
)

target_compile_options(LetheShardBootstrap PRIVATE
    /W4
    /GS      # buffer security check
    /sdl     # additional security checks
    /O2
)

target_link_options(LetheShardBootstrap PRIVATE
    /DYNAMICBASE
    /NXCOMPAT
    /guard:cf
)

if(BUILD_TESTING)
    add_executable(LetheKR2ProtocolTest
        tests/key_release_protocol_test.c
    )
    target_link_libraries(LetheKR2ProtocolTest PRIVATE LetheKR2Protocol)
    add_executable(LetheKR2CryptoTest
        tests/key_release_crypto_test.c
    )
    target_link_libraries(LetheKR2CryptoTest PRIVATE LetheKR2Crypto)
    if(MSVC)
        target_compile_options(LetheKR2Protocol PRIVATE /W4 /WX /O2)
        target_compile_options(LetheKR2Crypto PRIVATE /W4 /WX /O2)
        target_compile_options(LetheKR2ProtocolTest PRIVATE /W4 /WX /O2)
        target_compile_options(LetheKR2CryptoTest PRIVATE /W4 /WX /O2)
    endif()
    add_test(
        NAME LetheKR2ProtocolVectors
        COMMAND LetheKR2ProtocolTest
            "${CMAKE_CURRENT_SOURCE_DIR}/../tests/vectors/key_release_v2.txt"
    )
    add_test(
        NAME LetheKR2CryptoVectors
        COMMAND LetheKR2CryptoTest
            "${CMAKE_CURRENT_SOURCE_DIR}/../tests/vectors/key_release_crypto_v2.txt"
    )
endif()
