#include <windows.h>
#include <cwchar>
// Fixed harmless job used to prove lifecycle controls before graphics execution.
int wmain(int argc, wchar_t** argv) {
    if (argc != 2 || !*argv[1]) return 64;
    unsigned long duration = 0;
    for (const wchar_t* c = argv[1]; *c; ++c) {
        if (*c < L'0' || *c > L'9' || duration > 5000) return 64;
        duration = duration * 10 + (*c - L'0');
    }
    if (duration > 5000) return 64;
    Sleep(static_cast<DWORD>(duration));
    return 0;
}
