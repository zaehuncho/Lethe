# ===========================================================================
# Lethe obfuscation pass plugin -- build configuration.
#
# Builds src/LetheObfuscation.cpp into a shared module (a .dll on Windows, a
# .so/.dylib elsewhere) that clang/opt loads as a new-PassManager pass plugin.
#
# Targeted at an INSTALLED LLVM 17 or 18 (new PassManager). It must be built
# with the SAME LLVM/Clang toolchain you will feed the plugin to -- a plugin
# resolves LLVM symbols against the loading process, so mixing versions or a
# Release-vs-Debug/RTTI mismatch will fail to load. See obfuscation/README.md.
# ===========================================================================

cmake_minimum_required(VERSION 3.20)
project(LetheObfuscation LANGUAGES CXX)

# --- Locate an installed LLVM via its CMake package -------------------------
# Point CMake at your LLVM install with -DLLVM_DIR=<prefix>/lib/cmake/llvm .
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Lethe: found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Lethe: using LLVMConfig.cmake from ${LLVM_DIR}")
message(STATUS "Lethe: LLVM include dir ${LLVM_INCLUDE_DIRS}")

if (LLVM_PACKAGE_VERSION VERSION_LESS "17.0"
    OR LLVM_PACKAGE_VERSION VERSION_GREATER_EQUAL "19.0")
  message(WARNING
    "Lethe was authored against LLVM 17/18. You have ${LLVM_PACKAGE_VERSION}. "
    "It may still build, but check the 'API NOTE' comments in "
    "src/LetheObfuscation.cpp (registerOptimizerLastEPCallback signature, "
    "StringRef::starts_with, Demote*ToStack) for your version.")
endif()

# Pull in LLVM's CMake helpers (AddLLVM, HandleLLVMOptions) so we inherit the
# exact compile flags LLVM was built with (RTTI/EH/warnings/visibility). This is
# what keeps a Windows plugin ABI-compatible with the host clang-cl.
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)
include(HandleLLVMOptions)

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND "${LLVM_DEFINITIONS}")
add_definitions(${LLVM_DEFINITIONS_LIST})
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 17)          # LLVM 17/18 headers require C++17
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- The plugin module ------------------------------------------------------
# MODULE => a loadable plugin (not linked into anything at build time).
add_library(LetheObfuscation MODULE src/LetheObfuscation.cpp)

# Match LLVM's RTTI setting. LLVM is almost always built with RTTI OFF; a
# mismatch produces link/load errors. HandleLLVMOptions usually applies this,
# but we set it explicitly for the plugin target to be safe.
if (NOT LLVM_ENABLE_RTTI)
  if (MSVC)
    target_compile_options(LetheObfuscation PRIVATE /GR-)
  else()
    target_compile_options(LetheObfuscation PRIVATE -fno-rtti)
  endif()
endif()

# --- Link the LLVM components we use ----------------------------------------
# The task specifies Core + Support + Passes. We additionally need TransformUtils
# because control-flow flattening calls DemoteRegToStack / DemotePHIToStack,
# which live in libLLVMTransformUtils. Analysis is pulled in transitively by
# Passes. llvm_map_components_to_libnames resolves these to the right library
# names for THIS install (static or shared LLVM).
llvm_map_components_to_libnames(LETHE_LLVM_LIBS
  core
  support
  passes
  transformutils)

target_link_libraries(LetheObfuscation PRIVATE ${LETHE_LLVM_LIBS})

# On some platforms/toolchains the plugin should tolerate LLVM symbols being
# resolved lazily from the loading process (opt/clang) rather than duplicated
# in the module. If you hit duplicate-symbol or "already registered" cl::opt
# errors at load time, prefer linking against a shared libLLVM
# (-DLLVM_LINK_LLVM_DYLIB=ON in your LLVM build) instead of the static archives.

# Keep the artifact name stable and extensionless-of-"lib": we want
# LetheObfuscation.dll (Windows) / LetheObfuscation.so (Unix).
set_target_properties(LetheObfuscation PROPERTIES
  PREFIX ""
  OUTPUT_NAME "LetheObfuscation")

# Windows/clang-cl: the plugin exports llvmGetPassPluginInfo via __declspec in
# the source. Nothing else is needed here, but if you build with the MSVC
# toolchain (cl.exe) rather than clang-cl, ensure the same LLVM you target was
# built with MSVC too.
