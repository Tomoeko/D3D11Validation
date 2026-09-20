// SPDX-License-Identifier: GPL-3.0-only
// Bounded native D3D11 draw capture for the fixed private Unity fixture.
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <shellapi.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define MAX_SHADER_BYTES (16U * 1024U * 1024U)
#define MAX_DRAWS 4096U
static const GUID shader_bytes_guid = {0x62d73867, 0x8a0a, 0x4fa1, {0xb4,0xd9,0x73,0x70,0x10,0x43,0xbe,0xc8}};
static HMODULE original;
static BOOL capture_enabled;
static HANDLE log_file = INVALID_HANDLE_VALUE;
static wchar_t output_directory[4096];
static SRWLOCK lock = SRWLOCK_INIT;
// Runtime probing and the final device can use distinct native implementations.
// Keep each original table independently; never forward through another context's table.
#define MAX_TABLES 4U
static struct { const ID3D11DeviceVtbl *table; ID3D11DeviceVtbl original; } devices[MAX_TABLES];
static struct { const ID3D11DeviceContextVtbl *table; ID3D11DeviceContextVtbl original; } contexts[MAX_TABLES];
static unsigned device_tables, context_tables;
static unsigned draw_count, interval_label, interval_start;
static DWORD interval_thread;
static volatile LONG trace_errors;


static void write_record(HANDLE file, const char *format, va_list args) {
    char line[4096];
    int size = vsnprintf(line, sizeof(line), format, args);
    DWORD written;
    if (size <= 0 || size >= (int)sizeof(line) || file == INVALID_HANDLE_VALUE ||
        !WriteFile(file, line, (DWORD)size, &written, NULL) || written != (DWORD)size)
        ExitProcess(91);
}

static void record(const char *format, ...) {
    if (strncmp(format, "error\t", 6) == 0) InterlockedIncrement(&trace_errors);
    va_list args;
    va_start(args, format);
    write_record(log_file, format, args);
    va_end(args);
}

static void device_record(HANDLE file, const char *format, ...) {
    va_list args;
    va_start(args, format);
    write_record(file, format, args);
    va_end(args);
}

static const char *field_utf8(const wchar_t *value, char *buffer, int capacity) {
    for (const wchar_t *p = value; *p; ++p) if (*p < 32) ExitProcess(94);
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, buffer, capacity, NULL, NULL)) ExitProcess(94);
    return buffer;
}

static void observe_device(ID3D11Device *device) {
    static ID3D11Device *observed;
    if (observed) {
        if (observed != device) record("error\tmultiple-devices\n");
        return;
    }
    observed = device;
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
    device_record(file, "schema\td3d11-unity-device/v1\nname\t%s\n", field_utf8(desc.Description, utf8, sizeof(utf8)));
    device_record(file, "vendorId\t%u\ndeviceId\t%u\nsubsystemId\t%u\nrevision\t%u\n", desc.VendorId, desc.DeviceId, desc.SubSysId, desc.Revision);
    device_record(file, "luidLow\t%lu\nluidHigh\t%lu\nsoftware\t0\nsessionId\t%lu\n", desc.AdapterLuid.LowPart, (ULONG)desc.AdapterLuid.HighPart, session);
    device_record(file, "featureLevel\t%u\ncreationFlags\t%u\n", (unsigned)ID3D11Device_GetFeatureLevel(device), ID3D11Device_GetCreationFlags(device));
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
            device_record(file, "runtime\t%s\n", field_utf8(path, utf8, sizeof(utf8)));
            ++count;
        }
    }
    if (count != 4 || !FlushFileBuffers(file) || !CloseHandle(file)) ExitProcess(94);
    IDXGIAdapter1_Release(adapter1);
    IDXGIAdapter_Release(adapter);
    IDXGIDevice_Release(dxgi_device);
}

static BOOL initialize(void) {
    if (original) return TRUE;
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
    int argc;
    wchar_t **args = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!args) return FALSE;
    unsigned outputs = 0, modes = 0;
    for (int i = 1; i < argc; ++i) {
        if (!wcscmp(args[i], L"-output") && i + 1 < argc) {
            if (wcslen(args[++i]) >= 4000) { LocalFree(args); return FALSE; }
            wcscpy(output_directory, args[i]);
            ++outputs;
        } else if (!wcscmp(args[i], L"-trace") && i + 1 < argc) {
            ++i;
            if (wcscmp(args[i], L"on") && wcscmp(args[i], L"off")) { LocalFree(args); return FALSE; }
            capture_enabled = !wcscmp(args[i], L"on");
            ++modes;
        }
    }
    LocalFree(args);
    if (outputs != 1 || modes != 1) return FALSE;
    wchar_t path[4096];
    if (swprintf(path, 4096, L"%ls\\draws.bin", output_directory) < 0) return FALSE;
    log_file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (log_file == INVALID_HANDLE_VALUE) return FALSE;
    wchar_t system[MAX_PATH], actual[MAX_PATH];
    UINT length = GetSystemDirectoryW(system, MAX_PATH);
    if (!length || length >= MAX_PATH - 11) return FALSE;
    wcscat(system, L"\\d3d11.dll");
    HMODULE loaded = LoadLibraryExW(system, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!loaded) return FALSE;
    DWORD actual_length = GetModuleFileNameW(loaded, actual, MAX_PATH);
    if (!actual_length || actual_length >= MAX_PATH || _wcsicmp(system, actual)) {
        FreeLibrary(loaded);
        return FALSE;
    }
    original = loaded;
    record("schema\td3d11-native-unity-draw/v1\n");
    record("capture\t%s\n", capture_enabled ? "on" : "off");
    return TRUE;
}

static void patch(void *slot, void *function) {
    DWORD previous, ignored;
    if (!VirtualProtect(slot, sizeof(void *), PAGE_READWRITE, &previous)) ExitProcess(92);
    InterlockedExchangePointer((PVOID volatile *)slot, function);
    if (!VirtualProtect(slot, sizeof(void *), previous, &ignored)) ExitProcess(92);
}

static void tag_shader(ID3D11DeviceChild *shader, const void *bytes, SIZE_T size) {
    if (!shader || !bytes || size < 32 || size > MAX_SHADER_BYTES ||
        FAILED(ID3D11DeviceChild_SetPrivateData(shader, &shader_bytes_guid, (UINT)size, bytes)))
        record("error\tshader-tag\n");
}

static const ID3D11DeviceVtbl *original_device(ID3D11Device *device) {
    const ID3D11DeviceVtbl *result = NULL;
    AcquireSRWLockShared(&lock);
    for (unsigned i = 0; i < device_tables; ++i)
        if (devices[i].table == device->lpVtbl) result = &devices[i].original;
    ReleaseSRWLockShared(&lock);
    if (!result) ExitProcess(95);
    return result;
}

static const ID3D11DeviceContextVtbl *original_context(ID3D11DeviceContext *context) {
    const ID3D11DeviceContextVtbl *result = NULL;
    AcquireSRWLockShared(&lock);
    for (unsigned i = 0; i < context_tables; ++i)
        if (contexts[i].table == context->lpVtbl) result = &contexts[i].original;
    ReleaseSRWLockShared(&lock);
    if (!result) ExitProcess(95);
    return result;
}

static HRESULT STDMETHODCALLTYPE create_vertex(ID3D11Device *device, const void *bytes, SIZE_T size,
                                               ID3D11ClassLinkage *linkage, ID3D11VertexShader **out) {
    HRESULT result = original_device(device)->CreateVertexShader(device, bytes, size, linkage, out);
    if (capture_enabled && SUCCEEDED(result) && out && *out) tag_shader((ID3D11DeviceChild *)*out, bytes, size);
    return result;
}
static HRESULT STDMETHODCALLTYPE create_pixel(ID3D11Device *device, const void *bytes, SIZE_T size,
                                              ID3D11ClassLinkage *linkage, ID3D11PixelShader **out) {
    HRESULT result = original_device(device)->CreatePixelShader(device, bytes, size, linkage, out);
    if (capture_enabled && SUCCEEDED(result) && out && *out) tag_shader((ID3D11DeviceChild *)*out, bytes, size);
    return result;
}

static int save_bound_shader(ID3D11DeviceChild *shader, unsigned draw, const wchar_t *stage) {
    if (!shader) return 0;
    UINT size = 0;
    if (FAILED(ID3D11DeviceChild_GetPrivateData(shader, &shader_bytes_guid, &size, NULL)) ||
        size < 32 || size > MAX_SHADER_BYTES) return -1;
    void *bytes = HeapAlloc(GetProcessHeap(), 0, size);
    if (!bytes) return -1;
    UINT copied = size;
    HRESULT got = ID3D11DeviceChild_GetPrivateData(shader, &shader_bytes_guid, &copied, bytes);
    wchar_t path[4096];
    HANDLE file = INVALID_HANDLE_VALUE;
    int status = -1;
    if (SUCCEEDED(got) && copied == size &&
        swprintf(path, 4096, L"%ls\\draw-%04u-%ls.bin", output_directory, draw, stage) > 0) {
        file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD written;
        if (file != INVALID_HANDLE_VALUE && WriteFile(file, bytes, size, &written, NULL) && written == size)
            status = (int)size;
    }
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    HeapFree(GetProcessHeap(), 0, bytes);
    return status;
}

static void observe_draw(ID3D11DeviceContext *context, const char *method, UINT count,
                         UINT instances, UINT start, INT base, UINT first_instance) {
    AcquireSRWLockExclusive(&lock);
    if (++draw_count > MAX_DRAWS) ExitProcess(93);
    if (!interval_label || interval_thread != GetCurrentThreadId())
        record("error\tunscoped-or-wrong-thread-draw\n");
    ID3D11VertexShader *vertex = NULL;
    ID3D11PixelShader *pixel = NULL;
    ID3D11GeometryShader *geometry = NULL;
    ID3D11HullShader *hull = NULL;
    ID3D11DomainShader *domain = NULL;
    UINT vertex_classes = 0, pixel_classes = 0;
    ID3D11DeviceContext_VSGetShader(context, &vertex, NULL, &vertex_classes);
    ID3D11DeviceContext_PSGetShader(context, &pixel, NULL, &pixel_classes);
    ID3D11DeviceContext_GSGetShader(context, &geometry, NULL, NULL);
    ID3D11DeviceContext_HSGetShader(context, &hull, NULL, NULL);
    ID3D11DeviceContext_DSGetShader(context, &domain, NULL, NULL);
    const int vs = capture_enabled ? save_bound_shader((ID3D11DeviceChild *)vertex, draw_count, L"vs") : 0;
    const int ps = capture_enabled ? save_bound_shader((ID3D11DeviceChild *)pixel, draw_count, L"ps") : 0;
    ID3D11Device *active_device = NULL;
    ID3D11DeviceContext_GetDevice(context, &active_device);
    if (!active_device) record("error\tmissing-active-device\n");
    else observe_device(active_device);
    const unsigned feature = active_device ? (unsigned)ID3D11Device_GetFeatureLevel(active_device) : 0;
    const unsigned flags = active_device ? ID3D11Device_GetCreationFlags(active_device) : 0;
    if (!vertex || !pixel || (capture_enabled && (vs < 1 || ps < 1)) || vertex_classes || pixel_classes || geometry || hull || domain ||
        ID3D11DeviceContext_GetType(context) != D3D11_DEVICE_CONTEXT_IMMEDIATE)
        record("error\tunsupported-draw-binding\n");
    record("active-device\t%u\t%u\t%u\t%u\n", draw_count, interval_label, feature, flags);
    if (active_device) ID3D11Device_Release(active_device);
    record("draw\t%u\t%s\t%u\t%u\t%u\t%d\t%u\t%u\t%lu\t%d\t%d\t%u\t%u\t%d\t%d\t%d\n",
           draw_count, method, count, instances, start, base, first_instance,
           (unsigned)ID3D11DeviceContext_GetType(context), GetCurrentThreadId(), vs, ps,
           vertex_classes, pixel_classes, geometry != NULL, hull != NULL, domain != NULL);
    if (vertex) ID3D11VertexShader_Release(vertex);
    if (pixel) ID3D11PixelShader_Release(pixel);
    if (geometry) ID3D11GeometryShader_Release(geometry);
    if (hull) ID3D11HullShader_Release(hull);
    if (domain) ID3D11DomainShader_Release(domain);
    ReleaseSRWLockExclusive(&lock);
}

static void STDMETHODCALLTYPE draw(ID3D11DeviceContext *c, UINT n, UINT start) {
    observe_draw(c, "Draw", n, 1, start, 0, 0); original_context(c)->Draw(c,n,start);
}
static void STDMETHODCALLTYPE draw_indexed(ID3D11DeviceContext *c, UINT n, UINT start, INT base) {
    observe_draw(c, "DrawIndexed", n, 1, start, base, 0); original_context(c)->DrawIndexed(c,n,start,base);
}
static void STDMETHODCALLTYPE draw_instanced(ID3D11DeviceContext *c, UINT n, UINT instances, UINT start, UINT first) {
    observe_draw(c,"DrawInstanced",n,instances,start,0,first); original_context(c)->DrawInstanced(c,n,instances,start,first);
}
static void STDMETHODCALLTYPE draw_indexed_instanced(ID3D11DeviceContext *c, UINT n, UINT instances, UINT start, INT base, UINT first) {
    observe_draw(c,"DrawIndexedInstanced",n,instances,start,base,first); original_context(c)->DrawIndexedInstanced(c,n,instances,start,base,first);
}
static void STDMETHODCALLTYPE draw_auto(ID3D11DeviceContext *c) {
    observe_draw(c,"DrawAuto",0,0,0,0,0); original_context(c)->DrawAuto(c);
}
static void STDMETHODCALLTYPE draw_indirect(ID3D11DeviceContext *c, ID3D11Buffer *b, UINT offset) {
    observe_draw(c,"DrawInstancedIndirect",0,0,offset,0,0); original_context(c)->DrawInstancedIndirect(c,b,offset);
}
static void STDMETHODCALLTYPE draw_indexed_indirect(ID3D11DeviceContext *c, ID3D11Buffer *b, UINT offset) {
    observe_draw(c,"DrawIndexedInstancedIndirect",0,0,offset,0,0); original_context(c)->DrawIndexedInstancedIndirect(c,b,offset);
}

static void hook_context(ID3D11DeviceContext *context) {
    if (!context) return;
    for (unsigned i = 0; i < context_tables; ++i)
        if (contexts[i].table == context->lpVtbl) return;
    if (context_tables == MAX_TABLES) ExitProcess(95);
    const ID3D11DeviceContextVtbl *context_table = context->lpVtbl;
    contexts[context_tables].table = context_table;
    contexts[context_tables++].original = *context_table;
#define HOOK_CONTEXT(member, function) patch((void *)&context_table->member, (void *)function)
    HOOK_CONTEXT(Draw, draw); HOOK_CONTEXT(DrawIndexed, draw_indexed);
    HOOK_CONTEXT(DrawInstanced, draw_instanced); HOOK_CONTEXT(DrawIndexedInstanced, draw_indexed_instanced);
    HOOK_CONTEXT(DrawAuto, draw_auto); HOOK_CONTEXT(DrawInstancedIndirect, draw_indirect);
    HOOK_CONTEXT(DrawIndexedInstancedIndirect, draw_indexed_indirect);
#undef HOOK_CONTEXT
    record("context\t%u\n", (unsigned)ID3D11DeviceContext_GetType(context));
}

static HRESULT STDMETHODCALLTYPE create_deferred(ID3D11Device *device, UINT flags, ID3D11DeviceContext **out) {
    record("error\tdeferred-context-outside-scope\n");
    return original_device(device)->CreateDeferredContext(device, flags, out);
}

static void hook_device(ID3D11Device *device, ID3D11DeviceContext *context) {
    if (!device) { record("error\tmissing-device\n"); return; }
    AcquireSRWLockExclusive(&lock);
    unsigned i;
    for (i = 0; i < device_tables; ++i)
        if (devices[i].table == device->lpVtbl) break;
    if (i == device_tables) {
        if (device_tables == MAX_TABLES) ExitProcess(95);
        const ID3D11DeviceVtbl *device_table = device->lpVtbl;
        devices[i].table = device_table;
        devices[device_tables++].original = *device_table;
        patch((void *)&device_table->CreateVertexShader, (void *)create_vertex);
        patch((void *)&device_table->CreatePixelShader, (void *)create_pixel);
        patch((void *)&device_table->CreateDeferredContext, (void *)create_deferred);
        record("device\t%u\t%u\n", (unsigned)ID3D11Device_GetFeatureLevel(device), ID3D11Device_GetCreationFlags(device));
    }
    ID3D11DeviceContext *borrowed = context;
    if (!borrowed) ID3D11Device_GetImmediateContext(device, &borrowed);
    hook_context(borrowed);
    if (!context && borrowed) ID3D11DeviceContext_Release(borrowed);
    ReleaseSRWLockExclusive(&lock);
}

HRESULT WINAPI D3D11CreateDevice(IDXGIAdapter *adapter, D3D_DRIVER_TYPE type, HMODULE software, UINT flags,
                                const D3D_FEATURE_LEVEL *levels, UINT level_count, UINT version,
                                ID3D11Device **device, D3D_FEATURE_LEVEL *level, ID3D11DeviceContext **context) {
    if (!initialize()) return E_FAIL;
    typedef HRESULT (WINAPI *Create)(IDXGIAdapter *,D3D_DRIVER_TYPE,HMODULE,UINT,const D3D_FEATURE_LEVEL *,UINT,UINT,ID3D11Device **,D3D_FEATURE_LEVEL *,ID3D11DeviceContext **);
    FARPROC address = GetProcAddress(original, "D3D11CreateDevice");
    Create create;
    _Static_assert(sizeof(create) == sizeof(address), "Windows procedure pointer size");
    memcpy(&create, &address, sizeof(create));
    if (!create) return E_FAIL;
    HRESULT result = create(adapter,type,software,flags,levels,level_count,version,device,level,context);
    record("create-device\t%08lx\n", (unsigned long)result);
    if (SUCCEEDED(result)) hook_device(device ? *device : NULL, context ? *context : NULL);
    return result;
}

HRESULT WINAPI D3D11CreateDeviceAndSwapChain(IDXGIAdapter *adapter,D3D_DRIVER_TYPE type,HMODULE software,UINT flags,
    const D3D_FEATURE_LEVEL *levels,UINT level_count,UINT version,const DXGI_SWAP_CHAIN_DESC *desc,IDXGISwapChain **swapchain,
    ID3D11Device **device,D3D_FEATURE_LEVEL *level,ID3D11DeviceContext **context) {
    if (!initialize()) return E_FAIL;
    typedef HRESULT (WINAPI *Create)(IDXGIAdapter *,D3D_DRIVER_TYPE,HMODULE,UINT,const D3D_FEATURE_LEVEL *,UINT,UINT,const DXGI_SWAP_CHAIN_DESC *,IDXGISwapChain **,ID3D11Device **,D3D_FEATURE_LEVEL *,ID3D11DeviceContext **);
    FARPROC address = GetProcAddress(original,"D3D11CreateDeviceAndSwapChain");
    Create create;
    _Static_assert(sizeof(create) == sizeof(address), "Windows procedure pointer size");
    memcpy(&create, &address, sizeof(create));
    if (!create) return E_FAIL;
    HRESULT result = create(adapter,type,software,flags,levels,level_count,version,desc,swapchain,device,level,context);
    record("create-swapchain\t%08lx\n",(unsigned long)result);
    if (SUCCEEDED(result)) hook_device(device ? *device : NULL,context ? *context : NULL);
    return result;
}

UINT WINAPI DXBCTraceBegin(UINT label) {
    AcquireSRWLockExclusive(&lock);
    const BOOL valid = original && context_tables && label && !interval_label && !trace_errors;
    if (valid) {
        interval_label = label; interval_start = draw_count; interval_thread = GetCurrentThreadId();
        record("begin\t%u\t%lu\n", label, interval_thread);
    }
    ReleaseSRWLockExclusive(&lock);
    return valid ? 1 : 0;
}

UINT WINAPI DXBCTraceEnd(UINT label) {
    AcquireSRWLockExclusive(&lock);
    const BOOL valid = interval_label == label && label && !trace_errors &&
                       interval_thread == GetCurrentThreadId() && draw_count == interval_start + 1;
    record("end\t%u\t%u\t%ld\n", label, draw_count - interval_start, trace_errors);
    interval_label = 0;
    ReleaseSRWLockExclusive(&lock);
    return valid ? 1 : 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(instance); }
    return TRUE;
}
