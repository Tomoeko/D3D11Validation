// SPDX-License-Identifier: GPL-3.0-only
// Shared actual-device identity for draw capture and post-draw observation.
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include "graphics_identity.h"
#include <dxgi1_2.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

void validation_write_record(HANDLE file, const char *format, va_list args) {
    char line[4096];
    int size = vsnprintf(line, sizeof(line), format, args);
    DWORD written;
    if (size <= 0 || size >= (int)sizeof(line) || file == INVALID_HANDLE_VALUE ||
        !WriteFile(file, line, (DWORD)size, &written, NULL) || written != (DWORD)size)
        ExitProcess(91);
}

BOOL validation_process_allowed(void) {
    if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version")) return FALSE;
    DWORD session;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &session) || session != 0) return FALSE;
    HANDLE token;
    TOKEN_ELEVATION elevation;
    DWORD size;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return FALSE;
    BOOL standard = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)
        && !elevation.TokenIsElevated;
    CloseHandle(token);
    wchar_t user[256];
    size = 256;
    if (!standard || !GetUserNameW(user, &size) || _wcsicmp(user, L"d3d11validator")) return FALSE;
    return TRUE;
}

HMODULE validation_native_runtime(BOOL load) {
    wchar_t system[MAX_PATH], actual[MAX_PATH];
    UINT length = GetSystemDirectoryW(system, MAX_PATH);
    if (!length || length >= MAX_PATH - 11) return NULL;
    wcscat(system, L"\\d3d11.dll");
    HMODULE loaded = load ? LoadLibraryExW(system, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32) : GetModuleHandleW(system);
    if (!loaded) return NULL;
    DWORD actual_length = GetModuleFileNameW(loaded, actual, MAX_PATH);
    if (!actual_length || actual_length >= MAX_PATH || _wcsicmp(system, actual)) {
        if (load) FreeLibrary(loaded);
        return NULL;
    }
    return loaded;
}

void validation_record(HANDLE file, const char *format, ...) {
    va_list args;
    va_start(args, format);
    validation_write_record(file, format, args);
    va_end(args);
}

static const char *field_utf8(const wchar_t *value, char *buffer, int capacity) {
    for (const wchar_t *p = value; *p; ++p) if (*p < 32) ExitProcess(94);
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, buffer, capacity, NULL, NULL)) ExitProcess(94);
    return buffer;
}

void validation_observe_device(ID3D11Device *device, const wchar_t *output_directory, HMODULE original) {
    static ID3D11Device *observed;
    if (observed) {
        if (observed != device) ExitProcess(94);
        return;
    }
    observed = device;
    ID3D11Device_AddRef(observed); // Keep identity stable until process exit.
    IDXGIDevice *dxgi_device = NULL;
    IDXGIAdapter *adapter = NULL;
    IDXGIAdapter1 *adapter1 = NULL;
    DXGI_ADAPTER_DESC1 desc;
    if (FAILED(ID3D11Device_QueryInterface(device, &IID_IDXGIDevice, (void **)&dxgi_device)) ||
        FAILED(IDXGIDevice_GetAdapter(dxgi_device, &adapter)) ||
        FAILED(IDXGIAdapter_QueryInterface(adapter, &IID_IDXGIAdapter1, (void **)&adapter1)) ||
        FAILED(IDXGIAdapter1_GetDesc1(adapter1, &desc))) ExitProcess(94);
    if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) ExitProcess(94);
    wchar_t path[4096];
    if (swprintf(path, 4096, L"%ls\\device.bin", output_directory) < 0) ExitProcess(94);
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    char utf8[4096];
    DWORD session;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &session) || session != 0) ExitProcess(94);
    validation_record(file, "schema\td3d11-unity-device/v1\nname\t%s\n", field_utf8(desc.Description, utf8, sizeof(utf8)));
    validation_record(file, "vendorId\t%u\ndeviceId\t%u\nsubsystemId\t%u\nrevision\t%u\n", desc.VendorId, desc.DeviceId, desc.SubSysId, desc.Revision);
    validation_record(file, "luidLow\t%lu\nluidHigh\t%lu\nsoftware\t0\nsessionId\t%lu\n", desc.AdapterLuid.LowPart, (ULONG)desc.AdapterLuid.HighPart, session);
    validation_record(file, "featureLevel\t%u\ncreationFlags\t%u\n", (unsigned)ID3D11Device_GetFeatureLevel(device), ID3D11Device_GetCreationFlags(device));
    HMODULE modules[1024];
    DWORD bytes;
    if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &bytes) || bytes > sizeof(modules)) ExitProcess(94);
    unsigned count = 0;
    for (DWORD i = 0; i < bytes / sizeof(HMODULE); ++i) {
        DWORD length = GetModuleFileNameW(modules[i], path, 4096);
        if (!length || length >= 4096) ExitProcess(94);
        const wchar_t *name = wcsrchr(path, L'\\');
        if (!name) ExitProcess(94);
        ++name;
        if (modules[i] == original || !_wcsicmp(name, L"dxgi.dll") ||
            !_wcsicmp(name, L"nvldumdx.dll") || !_wcsicmp(name, L"nvwgf2umx.dll")) {
            validation_record(file, "runtime\t%s\n", field_utf8(path, utf8, sizeof(utf8)));
            ++count;
        }
    }
    if (count != 4 || !FlushFileBuffers(file) || !CloseHandle(file)) ExitProcess(94);
    IDXGIAdapter1_Release(adapter1);
    IDXGIAdapter_Release(adapter);
    IDXGIDevice_Release(dxgi_device);
}
