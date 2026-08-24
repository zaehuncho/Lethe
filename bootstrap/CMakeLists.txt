cmake_minimum_required(VERSION 3.20)
project(OrionBootstrap C)

set(CMAKE_C_STANDARD 11)

add_executable(OrionLauncher WIN32 shard_bootstrap.c)

target_link_libraries(OrionLauncher PRIVATE
    kernel32
    bcrypt
    winhttp
    advapi32
    shlwapi
)

target_compile_definitions(OrionLauncher PRIVATE
    _CRT_SECURE_NO_WARNINGS
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
)

target_compile_options(OrionLauncher PRIVATE
    /W4
    /GS      # buffer security check
    /sdl     # additional security checks
    /O2
)

target_link_options(OrionLauncher PRIVATE
    /DYNAMICBASE
    /NXCOMPAT
    /guard:cf
)
