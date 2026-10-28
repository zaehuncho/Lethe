#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* These helpers have no network, token, cache, or shard role. */
int lethe_sha256_file_handle(HANDLE file, char output_hex[65]);
int lethe_current_process_elevated(int *elevated);
int lethe_launch_sibling_broker(const char *install_directory);
