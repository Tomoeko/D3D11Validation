// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <windows.h>
#include <d3d11.h>
#include <stdarg.h>

BOOL validation_process_allowed(void);
HMODULE validation_native_runtime(BOOL load);
void validation_write_record(HANDLE file, const char *format, va_list args);
void validation_record(HANDLE file, const char *format, ...);
void validation_observe_device(ID3D11Device *device, const wchar_t *output_directory, HMODULE original);
