cmake_minimum_required(VERSION 3.20)
project(lethe_stub C ASM_MASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(lethe_stub_x64 SHARED
    src/stub_main.c
    src/pe_loader.c
    src/crypto.c
    src/key_scatter.c
    src/tls_anchor.c
    src/stubrt.c
    src/antidebug.c
    src/antidump.c
    src/memguard.c
    src/daedalus_vm.c
    src/daedalus_trampoline.asm
    src/miniz.c
    src/chkstk.asm
    # Decoy imports (user32/advapi32/ole32/shell32/gdi32/shlwapi): never called,
    # pulls those DLLs into the IAT so the packed binary's import graph looks
    # like a normal Windows app instead of a bare packer stub. See file header.
    src/stub_junk_imports.c
)

target_include_directories(lethe_stub_x64 PRIVATE src)
target_link_libraries(lethe_stub_x64 PRIVATE kernel32)

# Freestanding: no CRT, no default libs, no DLL entry point.
target_link_options(lethe_stub_x64 PRIVATE
    /NODEFAULTLIB
    /NOENTRY
    /DYNAMICBASE
    /NXCOMPAT
    /HIGHENTROPYVA
)

# Vendored miniz: strip to inflate-only (no stdio/time/archive/zip writer),
# lower warning level (we don't own this code).
set_source_files_properties(src/miniz.c PROPERTIES
    COMPILE_OPTIONS "/W3;/WX-"
    COMPILE_DEFINITIONS "MINIZ_NO_STDIO;MINIZ_NO_TIME;MINIZ_NO_DEFLATE_APIS;MINIZ_NO_ARCHIVE_APIS;MINIZ_NO_ZLIB_COMPATIBLE_NAMES"
)

# Key-binding integrity: the builder hashes .text to derive the AES key.
# /guard:cf inserts extra call-site checks that change .text content and
# require relocations inside .text, breaking both the hash and the
# reloc-free .text assertion. Deliberately disabled.
# Apply C compiler options to .c files only (not MASM .asm files).
file(GLOB _C_SOURCES src/*.c)
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set_source_files_properties(${_C_SOURCES} PROPERTIES
        COMPILE_OPTIONS "/W4;/GS-;/Oi;/O2;-fno-builtin;-Wno-missing-field-initializers;-Wno-missing-braces;-Wno-unused-but-set-variable;-Wno-unknown-pragmas;-Wno-ignored-pragma-intrinsic;-Wno-inconsistent-dllimport"
    )
else()
    set_source_files_properties(${_C_SOURCES} PROPERTIES
        COMPILE_OPTIONS "/W4;/WX;/GS-;/Oi;/O2"
    )
endif()

# Strip /guard:cf that CMake may inject via CMAKE_C_FLAGS or toolchain files.
foreach(_flag CMAKE_C_FLAGS CMAKE_C_FLAGS_RELEASE CMAKE_C_FLAGS_RELWITHDEBINFO)
    string(REPLACE "/guard:cf" "" ${_flag} "${${_flag}}")
endforeach()
foreach(_flag CMAKE_SHARED_LINKER_FLAGS CMAKE_SHARED_LINKER_FLAGS_RELEASE CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO)
    string(REPLACE "/guard:cf" "" ${_flag} "${${_flag}}")
endforeach()

# History-keyed self-decrypting Daedalus bytecode (daedalus_rolling.c). OFF by
# default so the shipped stub is unchanged; ON compiles the runtime rolling
# decoder AND makes generate_programs emit 'VR' containers (pack-time encoder +
# differential proof: daedalus/daedalus_rolling.py + tests/test_rolling_bytecode.py).
# Declared before the shuffle block because that block reads it.
option(DVM_ROLLING "Compile+emit history-keyed rolling-bytecode virtualization" OFF)
# Observation-poison: fold an anti-instrumentation signal into the rolling
# accumulator so a debugger silently mis-keys (zero-FP on clean runs). Kill-
# switch; default ON when rolling is on.
# NOTE: keep DVM_ROLLING/DVM_ROLL_POISON OFF for any build you intend to attach a
# debugger to yourself -- the poison's failure mode is an opaque decrypt failure,
# not a clean exit, so a self-debug session would look like corruption.
option(DVM_ROLL_POISON "Fold anti-instrumentation poison into rolling decode" ON)
if(DVM_ROLLING)
    target_sources(lethe_stub_x64 PRIVATE src/daedalus_rolling.c)
    target_compile_definitions(lethe_stub_x64 PRIVATE DVM_ROLLING)
    if(DVM_ROLL_POISON)
        target_compile_definitions(lethe_stub_x64 PRIVATE DVM_ROLL_POISON)
    endif()
endif()

# Kalypso (cipher/kalypso.c) -- the sound ChaCha20-based custom cipher.
# Used as the memguard per-page hot-path cipher, replacing the old repeating-XOR
# pad (trivially breakable) with a real stream cipher. Referenced from its single
# tested source (KAT: tests/test_kalypso.py + the C KALYPSO_KAT_MAIN) with the
# same hardening flags as the stub .c files.
set(_kalypso_dir "${CMAKE_CURRENT_SOURCE_DIR}/../cipher")
target_sources(lethe_stub_x64 PRIVATE "${_kalypso_dir}/kalypso.c")
target_include_directories(lethe_stub_x64 PRIVATE "${_kalypso_dir}")
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set_source_files_properties("${_kalypso_dir}/kalypso.c" PROPERTIES
        COMPILE_OPTIONS "/W4;/GS-;/Oi;/O2;-fno-builtin")
else()
    set_source_files_properties("${_kalypso_dir}/kalypso.c" PROPERTIES
        COMPILE_OPTIONS "/W4;/WX;/GS-;/Oi;/O2")
endif()
option(MEMGUARD_KALYPSO "Use Kalypso (not repeating-XOR) for the memguard hot-path" ON)
if(MEMGUARD_KALYPSO)
    target_compile_definitions(lethe_stub_x64 PRIVATE MEMGUARD_KALYPSO)
endif()

option(DVM_SHUFFLE_OPCODES "Enable per-build opcode shuffling for Daedalus VM" ON)

# Guard against a silent security DOWNGRADE: the rolling ('VR') containers are
# emitted by generate_programs, which runs only inside the shuffle block below.
# So DVM_ROLLING without DVM_SHUFFLE_OPCODES would compile the rolling decoder +
# poison but ship un-rolled canonical plaintext bytecode (no 'VR' magic), and the
# runtime would silently route to the plaintext path -- protection the operator
# thinks is on would be off. Fail loudly instead.
if(DVM_ROLLING AND NOT DVM_SHUFFLE_OPCODES)
    message(FATAL_ERROR
        "DVM_ROLLING requires DVM_SHUFFLE_OPCODES=ON (the rolling 'VR' encoder "
        "runs inside the shuffle step). Enable DVM_SHUFFLE_OPCODES or disable "
        "DVM_ROLLING -- otherwise the stub would ship un-rolled bytecode.")
endif()

if(DVM_SHUFFLE_OPCODES)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(_dvm_daedalus_dir  "${CMAKE_CURRENT_SOURCE_DIR}/../daedalus")
    set(_dvm_shuffler    "${_dvm_daedalus_dir}/shuffle_opcodes.py")
    set(_dvm_progen      "${_dvm_daedalus_dir}/generate_programs.py")
    set(_dvm_asm         "${_dvm_daedalus_dir}/daedalus_asm.py")
    set(_dvm_programs_dir "${_dvm_daedalus_dir}/programs")
    set(_dvm_shuffled_h  "${CMAKE_CURRENT_BINARY_DIR}/daedalus_opcodes_shuffled.h")
    set(_dvm_shuffled_py "${_dvm_daedalus_dir}/daedalus_opcodes_shuffled.py")
    set(_dvm_programs_h  "${CMAKE_CURRENT_BINARY_DIR}/daedalus_programs_shuffled.h")

    # Step 1: mint a fresh per-build opcode permutation.
    add_custom_command(
        OUTPUT "${_dvm_shuffled_h}" "${_dvm_shuffled_py}"
        COMMAND ${Python3_EXECUTABLE} "${_dvm_shuffler}" generate
                --c-header "${_dvm_shuffled_h}"
                --py-dict "${_dvm_shuffled_py}"
        COMMENT "Shuffling Daedalus VM opcodes (per-build randomization)"
        DEPENDS "${_dvm_shuffler}"
        VERBATIM
    )

    # Step 2: re-assemble the .vasm sources against the shuffled map so the
    # bytecode blobs in daedalus_programs.h match the interpreter's decode.
    # Without this the interpreter would misdispatch canonical bytecode and
    # every packed binary would fail crypto_derive_key. All .vasm files are
    # DEPENDS so a source edit forces a rebuild.
    file(GLOB _dvm_vasm_sources "${_dvm_programs_dir}/*.vasm")
    # When DVM_ROLLING is ON, emit history-keyed rolling ('VR') containers so
    # the crypto-critical programs ship as self-decrypting ciphertext. MBA
    # arithmetic rewrite is always on (proven semantics-preserving).
    if(DVM_ROLLING)
        set(_dvm_rolling_flag "--rolling")
    else()
        set(_dvm_rolling_flag "")
    endif()
    add_custom_command(
        OUTPUT "${_dvm_programs_h}"
        COMMAND ${Python3_EXECUTABLE} "${_dvm_progen}"
                --shuffled-map "${_dvm_shuffled_py}"
                --programs-dir "${_dvm_programs_dir}"
                --output       "${_dvm_programs_h}"
                ${_dvm_rolling_flag}
        COMMENT "Assembling Daedalus VM programs (shuffled + MBA${_dvm_rolling_flag})"
        DEPENDS "${_dvm_progen}" "${_dvm_asm}" "${_dvm_shuffled_py}"
                "${_dvm_daedalus_dir}/daedalus_mba.py"
                "${_dvm_daedalus_dir}/daedalus_rolling.py"
                "${_dvm_daedalus_dir}/daedalus_ref.py"
                ${_dvm_vasm_sources}
        VERBATIM
    )

    add_custom_target(daedalus_shuffle
        DEPENDS "${_dvm_shuffled_h}" "${_dvm_programs_h}")
    add_dependencies(lethe_stub_x64 daedalus_shuffle)
    target_include_directories(lethe_stub_x64 PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
    target_compile_definitions(lethe_stub_x64 PRIVATE DVM_SHUFFLED)
endif()

# History-keyed self-decrypting Daedalus bytecode (daedalus_rolling.c). OFF by
# default so the shipped stub is byte-identical to today; turn ON to compile the
# runtime rolling decoder (pack-time encoder + differential proof live in
# daedalus/daedalus_rolling.py + tests/test_rolling_bytecode.py).
# Diagnostic tracing (writes lethe_diag.txt with per-step markers). Enable with
# -DLETHE_ENABLE_DIAG=ON when hunting a stub-loader regression; OFF by default
# so shipped builds don't leak side-channel telemetry to disk or announce a
# packer stub to an analyst who spots the file appearing.
option(LETHE_ENABLE_DIAG "Emit lethe_diag.txt trace from pe_loader (debug only)" OFF)
if(LETHE_ENABLE_DIAG)
    target_compile_definitions(lethe_stub_x64 PRIVATE LETHE_DIAG)
endif()

# Prebuilt output: copy the DLL to stub/prebuilt/ after build.
set(PREBUILT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/prebuilt")
add_custom_command(TARGET lethe_stub_x64 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${PREBUILT_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:lethe_stub_x64>"
        "${PREBUILT_DIR}/lethe_stub_x64.dll"
    COMMENT "Copying stub to prebuilt/"
)
