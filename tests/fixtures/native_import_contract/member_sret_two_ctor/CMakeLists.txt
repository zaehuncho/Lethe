cmake_minimum_required(VERSION 3.20)
project(lethe_xfg_member_two_ctor_fixture CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(xfg_member_two_support SHARED support.cpp)
target_compile_definitions(xfg_member_two_support PRIVATE STRINGLIKE_SUPPORT_EXPORTS)
target_compile_options(xfg_member_two_support PRIVATE /W4 /WX /O2 /GS- /guard:cf /guard:xfg /EHsc)
target_link_options(xfg_member_two_support PRIVATE
  /guard:cf /guard:xfg /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO /OPT:NOICF)

add_library(xfg_member_two SHARED member.cpp)
target_include_directories(xfg_member_two PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(xfg_member_two PRIVATE /W4 /WX /O2 /GS- /guard:cf /guard:xfg /EHsc)
target_link_options(xfg_member_two PRIVATE
  /guard:cf /guard:xfg /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO /OPT:NOICF)
target_link_libraries(xfg_member_two PRIVATE xfg_member_two_support)

add_executable(xfg_member_two_host host.cpp)
target_include_directories(xfg_member_two_host PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(xfg_member_two_host PRIVATE /W4 /WX /O2 /GS- /guard:cf /guard:xfg /EHsc)
target_link_options(xfg_member_two_host PRIVATE
  /guard:cf /guard:xfg /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO /OPT:NOICF)
