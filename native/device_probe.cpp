// A bounded native D3D11 preflight. Shader comparison is a separate qualification.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wtsapi32.h>
#include <psapi.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
template<class T> struct Com {
    T* value = nullptr;
    ~Com() { if (value) value->Release(); }
    Com() = default;
    Com(const Com&) = delete;
    Com& operator=(const Com&) = delete;
    T** out() { if (value) throw std::runtime_error("nonempty COM output"); return &value; }
    T* operator->() const { return value; }
};
void require(bool success, const char* operation) {
    if (!success) throw std::runtime_error(operation);
}
void check(HRESULT status, const char* operation) { require(SUCCEEDED(status), operation); }
std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    require(size > 0, "UTF-8 sizing");
    std::string result(size, '\0');
    require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), size, nullptr, nullptr) == size, "UTF-8 encoding");
    return result;
}
std::string json_quote(const std::wstring& value) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : utf8(value)) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c);
        else out << c;
    }
    out << '"';
    return out.str();
}
std::wstring module_path(HMODULE module) {
    std::array<wchar_t, 32768> buffer{};
    DWORD count = GetModuleFileNameW(module, buffer.data(), DWORD(buffer.size()));
    require(count > 0 && count < buffer.size(), "module path");
    return {buffer.data(), count};
}
HMODULE system_module(const wchar_t* name) {
    HMODULE module = LoadLibraryExW(name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    require(module != nullptr, "native system module load");
    std::array<wchar_t, MAX_PATH> directory{};
    require(GetSystemDirectoryW(directory.data(), DWORD(directory.size())) != 0, "system directory");
    const auto expected = std::wstring(directory.data()) + L"\\" + name;
    require(_wcsicmp(module_path(module).c_str(), expected.c_str()) == 0, "unexpected runtime location");
    return module;
}
int session_value(WTS_INFO_CLASS kind, bool word = false) {
    LPWSTR data = nullptr;
    DWORD size = 0;
    require(WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
        kind, &data, &size), "current session query");
    const bool valid = size >= (word ? sizeof(USHORT) : sizeof(int));
    int value = valid ? (word ? *reinterpret_cast<USHORT*>(data) : *reinterpret_cast<int*>(data)) : -1;
    WTSFreeMemory(data);
    require(valid, "short session record");
    return value;
}
void write_new(const std::wstring& path, const void* data, DWORD size) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    require(file != INVALID_HANDLE_VALUE, "exclusive output creation");
    DWORD written = 0;
    bool complete = WriteFile(file, data, size, &written, nullptr) && written == size && FlushFileBuffers(file);
    CloseHandle(file);
    require(complete, "complete output write");
}
std::string loaded_modules() {
    std::array<HMODULE, 1024> modules{};
    DWORD bytes = 0;
    require(EnumProcessModules(GetCurrentProcess(), modules.data(), DWORD(sizeof(modules)), &bytes)
        && bytes <= sizeof(modules), "module inventory");
    std::vector<std::wstring> paths;
    for (DWORD i = 0; i < bytes / sizeof(HMODULE); ++i) paths.push_back(module_path(modules[i]));
    std::sort(paths.begin(), paths.end());
    std::ostringstream result;
    result << '[';
    for (size_t i = 0; i < paths.size(); ++i) { if (i) result << ','; result << json_quote(paths[i]); }
    result << ']';
    return result.str();
}
}

int wmain(int argc, wchar_t** argv) {
    // Operator supplies an empty, owned output directory. The job API never
    // accepts this path or arbitrary executable arguments from a remote request.
    const bool session_zero = argc > 2 && std::wstring(argv[argc - 1]) == L"--session0";
    if (session_zero) --argc;
    if (argc != 2 && argc != 3 && argc != 5) return 64;
    try {
        // Omitting the ordinal performs inventory only. Rendering requires an
        // explicit operator selection which the protected worker pins by LUID.
        // Ordinal selection is retained for rejection controls and operator diagnostics.
        UINT selected_index = UINT_MAX;
        const bool select_luid = argc == 5;
        LUID requested_luid{};
        if (select_luid) {
            require(std::wstring(argv[2]) == L"--luid", "invalid selection mode");
            auto parse_word = [](const wchar_t* text) {
                wchar_t* end = nullptr;
                unsigned long long value = wcstoull(text, &end, 10);
                require(text[0] >= L'0' && text[0] <= L'9' && end && !*end && value <= UINT_MAX,
                    "invalid adapter LUID");
                return static_cast<DWORD>(value);
            };
            requested_luid.LowPart = parse_word(argv[3]);
            requested_luid.HighPart = static_cast<LONG>(parse_word(argv[4]));
        }
        if (argc == 3) {
            wchar_t* end = nullptr;
            unsigned long index = wcstoul(argv[2], &end, 10);
            require(argv[2][0] >= L'0' && argv[2][0] <= L'9' && end && !*end && index < 64,
                "invalid adapter ordinal");
            selected_index = UINT(index);
        }
        const std::wstring output = argv[1];
        DWORD attributes = GetFileAttributesW(output.c_str());
        require(attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)
            && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "owned output directory");
        require(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version") == nullptr, "Wine runtime rejected");
        DWORD session = 0;
        require(ProcessIdToSessionId(GetCurrentProcessId(), &session) &&
            (session_zero ? session == 0 : session != 0), "requested process session");
        HANDLE token = nullptr;
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "process token");
        TOKEN_ELEVATION elevation{};
        DWORD returned = 0;
        bool token_ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned);
        CloseHandle(token);
        require(token_ok && !elevation.TokenIsElevated, "standard process token");
        std::array<wchar_t, 256> user{};
        DWORD user_length = DWORD(user.size());
        require(GetUserNameW(user.data(), &user_length)
            && _wcsicmp(user.data(), L"d3d11validator") == 0, "dedicated account required");
        // WTS client/presentation state is inapplicable to the noninteractive
        // offscreen context. -1 records that explicitly; it is not a console.
        const int protocol = session_zero ? -1 : session_value(WTSClientProtocolType, true);
        const int state = session_zero ? -1 : session_value(WTSConnectState);
        require(session_zero || ((protocol == 0 || protocol == 2) && (state == WTSActive || state == WTSDisconnected)),
            "unsupported interactive session state");
        HMODULE dxgi = system_module(L"dxgi.dll");
        HMODULE d3d11 = system_module(L"d3d11.dll");
        using CreateFactory = HRESULT(WINAPI*)(REFIID, void**);
        auto create_factory = reinterpret_cast<CreateFactory>(GetProcAddress(dxgi, "CreateDXGIFactory1"));
        auto create_device = reinterpret_cast<PFN_D3D11_CREATE_DEVICE>(GetProcAddress(d3d11, "D3D11CreateDevice"));
        require(create_factory && create_device, "native runtime exports");
        Com<IDXGIFactory1> factory;
        check(create_factory(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(factory.out())), "DXGI factory");
        Com<IDXGIAdapter1> selected;
        DXGI_ADAPTER_DESC1 selected_desc{};
        std::ostringstream adapters;
        adapters << "{\"schema\":\"d3d11-adapter-inventory/v2\",\"qualified\":false,\"adapters\":[";
        for (UINT index = 0;; ++index) {
            require(index < 64, "adapter enumeration limit");
            Com<IDXGIAdapter1> candidate;
            HRESULT result = factory->EnumAdapters1(index, candidate.out());
            if (result == DXGI_ERROR_NOT_FOUND) break;
            check(result, "adapter enumeration");
            DXGI_ADAPTER_DESC1 description{};
            check(candidate->GetDesc1(&description), "adapter description");
            if (index) adapters << ',';
            adapters << "{\"ordinal\":" << index << ",\"name\":" << json_quote(description.Description)
                << ",\"vendorId\":" << description.VendorId << ",\"deviceId\":" << description.DeviceId
                << ",\"subsystemId\":" << description.SubSysId << ",\"revision\":" << description.Revision
                << ",\"flags\":" << description.Flags << ",\"dedicatedVideoMemory\":" << description.DedicatedVideoMemory
                << ",\"luidLow\":" << description.AdapterLuid.LowPart
                << ",\"luidHigh\":" << UINT(description.AdapterLuid.HighPart) << '}';
            const bool identity_matches = select_luid
                ? description.AdapterLuid.LowPart == requested_luid.LowPart &&
                    description.AdapterLuid.HighPart == requested_luid.HighPart
                : index == selected_index;
            if (identity_matches && description.VendorId == 0xffff &&
                std::wstring(description.Description) == L"Example Hardware Adapter" &&
                !(description.Flags & DXGI_ADAPTER_FLAG_SOFTWARE)) {
                require(!selected.value, "ambiguous adapter identity");
                selected_index = index;
                selected.value = candidate.value;
                candidate.value = nullptr;
                selected_desc = description;
            }
        }
        adapters << "]}\n";
        const auto adapter_text = adapters.str();
        write_new(output + L"\\adapters.json", adapter_text.data(), DWORD(adapter_text.size()));
        if (argc == 2) return 0;
        require(selected.value, "intended hardware adapter unavailable");
        const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
        constexpr UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
        D3D_FEATURE_LEVEL level{};
        Com<ID3D11Device> device;
        Com<ID3D11DeviceContext> context;
        check(create_device(selected.value, D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags,
            levels, 2, D3D11_SDK_VERSION, device.out(), &level, context.out()), "hardware device creation");
        Com<IDXGIDevice> dxgi_device;
        check(device->QueryInterface(__uuidof(IDXGIDevice), reinterpret_cast<void**>(dxgi_device.out())), "actual DXGI device");
        Com<IDXGIAdapter> actual_adapter;
        check(dxgi_device->GetAdapter(actual_adapter.out()), "actual device adapter");
        DXGI_ADAPTER_DESC actual{};
        check(actual_adapter->GetDesc(&actual), "actual adapter description");
        require(actual.VendorId == selected_desc.VendorId && actual.DeviceId == selected_desc.DeviceId
            && actual.AdapterLuid.LowPart == selected_desc.AdapterLuid.LowPart
            && actual.AdapterLuid.HighPart == selected_desc.AdapterLuid.HighPart, "actual adapter identity mismatch");
        D3D11_TEXTURE2D_DESC description{};
        description.Width = description.Height = 4;
        description.MipLevels = description.ArraySize = description.SampleDesc.Count = 1;
        description.Format = DXGI_FORMAT_R32G32B32A32_FLOAT;
        description.Usage = D3D11_USAGE_DEFAULT;
        description.BindFlags = D3D11_BIND_RENDER_TARGET;
        Com<ID3D11Texture2D> target;
        check(device->CreateTexture2D(&description, nullptr, target.out()), "offscreen render target");
        Com<ID3D11RenderTargetView> view;
        check(device->CreateRenderTargetView(target.value, nullptr, view.out()), "render target view");
        const std::array<float, 4> color{0.25f, 0.5f, 0.75f, 1.0f};
        context->ClearRenderTargetView(view.value, color.data());
        description.Usage = D3D11_USAGE_STAGING;
        description.BindFlags = 0;
        description.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        Com<ID3D11Texture2D> staging;
        check(device->CreateTexture2D(&description, nullptr, staging.out()), "readback staging");
        context->CopyResource(staging.value, target.value);
        D3D11_MAPPED_SUBRESOURCE mapped{};
        check(context->Map(staging.value, 0, D3D11_MAP_READ, 0, &mapped), "raw GPU readback");
        std::array<float, 64> pixels{};
        const bool pitch_valid = mapped.RowPitch >= 4 * sizeof(color);
        if (pitch_valid) for (size_t row = 0; row < 4; ++row)
            std::memcpy(pixels.data() + row * 16,
                static_cast<const char*>(mapped.pData) + row * mapped.RowPitch, 4 * sizeof(color));
        context->Unmap(staging.value, 0);
        require(pitch_valid, "readback row pitch");
        for (size_t pixel = 0; pixel < 16; ++pixel)
            require(std::memcmp(pixels.data() + pixel * 4, color.data(), sizeof(color)) == 0, "bitwise clear readback mismatch");
        require(device->GetDeviceRemovedReason() == S_OK, "device removed");
        require(session_zero || (session_value(WTSClientProtocolType, true) == protocol
            && session_value(WTSConnectState) == state), "session changed during preflight");
        write_new(output + L"\\pixels.bin", pixels.data(), DWORD(sizeof(pixels)));
        std::ostringstream report;
        report << "{\"schema\":\"d3d11-device-preflight/v1\",\"nativeHardwarePreflightPassed\":true,"
            << "\"fullQualificationComplete\":false,\"operation\":\"clear-and-readback\",\"sessionId\":" << session
            << ",\"elevated\":false,\"clientProtocolType\":" << protocol << ",\"connectionState\":" << state
            << ",\"executionContext\":\"" << (session_zero ? "Session0" : "Interactive") << '"'
            << ",\"adapter\":{\"ordinal\":" << selected_index << ",\"name\":" << json_quote(actual.Description) << ",\"vendorId\":" << actual.VendorId
            << ",\"deviceId\":" << actual.DeviceId << ",\"subsystemId\":" << actual.SubSysId
            << ",\"revision\":" << actual.Revision << ",\"luidLow\":" << actual.AdapterLuid.LowPart
            << ",\"luidHigh\":" << UINT(actual.AdapterLuid.HighPart) << ",\"software\":false},\"featureLevel\":" << unsigned(level)
            << ",\"creationFlags\":" << device->GetCreationFlags() << ",\"format\":\"R32G32B32A32_FLOAT\","
            << "\"width\":4,\"height\":4,\"pixelBytes\":256,\"bitwiseReferenceMatch\":true,\"loadedModules\":"
            << loaded_modules() << "}\n";
        const auto text = report.str();
        write_new(output + L"\\report.json", text.data(), DWORD(text.size()));
        return 0;
    } catch (const std::exception& error) {
        // Operation labels are fixed strings, never host paths or credentials.
        fprintf(stderr, "Device preflight failed: %s\n", error.what());
        return 1;
    }
}
