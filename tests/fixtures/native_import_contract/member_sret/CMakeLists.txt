cmake_minimum_required(VERSION 3.20)
project(lethe_xfg_member_import_fixture CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(xfg_member_support SHARED support.asm)
set_target_properties(xfg_member_support PROPERTIES OUTPUT_NAME xfg_member_support)
target_link_options(xfg_member_support PRIVATE
  /INCREMENTAL:NO /OPT:NOICF /NXCOMPAT /CETCOMPAT:NO /NODEFAULTLIB
  /DYNAMICBASE:NO /EXPORT:xfg_copy_config /ENTRY:DllMain /MANIFEST:NO)

add_library(xfg_member SHARED member.cpp)
target_include_directories(xfg_member PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(xfg_member PRIVATE /W4 /WX /O2 /GS- /guard:cf /guard:xfg /EHsc)
target_link_options(xfg_member PRIVATE
  /INCREMENTAL:NO /OPT:NOICF /DYNAMICBASE /NXCOMPAT /guard:cf /guard:xfg)
target_link_libraries(xfg_member PRIVATE xfg_member_support)

add_executable(xfg_member_host host.cpp)
target_include_directories(xfg_member_host PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(xfg_member_host PRIVATE /W4 /WX /O2 /GS- /guard:cf /guard:xfg /EHsc)
target_link_options(xfg_member_host PRIVATE
  /INCREMENTAL:NO /OPT:NOICF /DYNAMICBASE /NXCOMPAT /guard:cf /guard:xfg)
