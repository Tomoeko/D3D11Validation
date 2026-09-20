// SPDX-License-Identifier: GPL-3.0-only
// Observe the actual render target after the draw, without intercepting D3D11.
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include "graphics_identity.h"
#include <stdio.h>

static UINT failure(const wchar_t *output, UINT code, const D3D11_TEXTURE2D_DESC *desc) {
    wchar_t path[4096];
    if (swprintf(path, 4096, L"%ls\\observer-failure.bin", output) < 0) return code;
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    validation_record(file, "schema\td3d11-observer-failure/v1\ncode\t%u\n", code);
    if (desc) validation_record(file, "texture\t%u\t%u\t%u\t%u\t%u\n", desc->Width,
                               desc->Height, desc->Format, desc->SampleDesc.Count, desc->BindFlags);
    CloseHandle(file);
    return code;
}

__declspec(dllexport) UINT WINAPI ValidationObserveTexture(ID3D11Resource *resource, const wchar_t *output) {
    static LONG observations;
    if (!output || wcslen(output) >= 4000 || !validation_process_allowed()) return 0;
    if (!resource) return failure(output, 10, NULL);
    if (InterlockedIncrement(&observations) > 2) return failure(output, 11, NULL);
    HMODULE runtime = validation_native_runtime(FALSE);
    if (!runtime) return failure(output, 12, NULL);
    ID3D11Texture2D *texture = NULL;
    if (FAILED(ID3D11Resource_QueryInterface(resource, &IID_ID3D11Texture2D, (void **)&texture))) return failure(output, 13, NULL);
    D3D11_TEXTURE2D_DESC desc;
    ID3D11Texture2D_GetDesc(texture, &desc);
    ID3D11Texture2D_Release(texture);
    if (desc.Width != 4 || desc.Height != 4 ||
        (desc.Format != DXGI_FORMAT_R32G32B32A32_FLOAT && desc.Format != DXGI_FORMAT_R32G32B32A32_TYPELESS) ||
        desc.SampleDesc.Count != 1 || !(desc.BindFlags & D3D11_BIND_RENDER_TARGET)) return failure(output, 14, &desc);
    ID3D11Device *device = NULL;
    ID3D11Resource_GetDevice(resource, &device);
    if (!device) return failure(output, 15, NULL);
    ID3D11DeviceContext *context = NULL;
    ID3D11Device_GetImmediateContext(device, &context);
    if (!context) return failure(output, 16, NULL);
    ID3D11RenderTargetView *view = NULL;
    ID3D11DeviceContext_OMGetRenderTargets(context, 1, &view, NULL);
    ID3D11DeviceContext_Release(context);
    if (!view) return failure(output, 17, NULL);
    ID3D11Resource *bound = NULL;
    ID3D11RenderTargetView_GetResource(view, &bound);
    D3D11_RENDER_TARGET_VIEW_DESC view_desc;
    ID3D11RenderTargetView_GetDesc(view, &view_desc);
    ID3D11RenderTargetView_Release(view);
    // Both pointers expose ID3D11Resource. Check canonical COM identity as well.
    IUnknown *expected_identity = NULL, *bound_identity = NULL;
    if (!bound || FAILED(ID3D11Resource_QueryInterface(resource, &IID_IUnknown, (void **)&expected_identity)) ||
        FAILED(ID3D11Resource_QueryInterface(bound, &IID_IUnknown, (void **)&bound_identity)))
        return failure(output, 18, NULL);
    const BOOL same = expected_identity == bound_identity;
    IUnknown_Release(expected_identity);
    IUnknown_Release(bound_identity);
    ID3D11Resource_Release(bound);
    if (!same || view_desc.Format != DXGI_FORMAT_R32G32B32A32_FLOAT ||
        view_desc.ViewDimension != D3D11_RTV_DIMENSION_TEXTURE2D || view_desc.Texture2D.MipSlice != 0)
        return failure(output, 19, &desc);
    validation_observe_device(device, output, runtime);
    ID3D11Device_Release(device);
    return 1;
}
