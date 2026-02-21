#include <Windows.h>
#include <cstdint>
#include <atomic>
#include <thread>
#include "MinHook.h"

#pragma pack(push, 1)
struct LevelRendererPlayer {
    uint8_t padding_x[0xFF0];
    float fov_x;
    uint8_t padding_y[0x1004 - 0xFF0 - 4];
    float fov_y;
};

struct LevelRenderer {
    uint8_t padding[0x430];
    LevelRendererPlayer* player;
};
#pragma pack(pop)

static std::atomic<uintptr_t> g_originalRenderLevel{ 0 };
static float g_zoomModifier = 1.0f;
constexpr float TARGET_ZOOM = 10.0f;

constexpr uint8_t RENDER_LEVEL_CALL_SIG[] = {
0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x32, 0xF6, 0x48, 0x8B, 0x8E
};

constexpr uint8_t RENDER_LEVEL_CALL_MASK[] = {
0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

uintptr_t FindPattern(uintptr_t base, size_t size, const uint8_t* pattern, const uint8_t* mask, size_t patternLen) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(base);
    for (size_t i = 0; i < size - patternLen; ++i) {
        bool found = true;
        for (size_t j = 0; j < patternLen; ++j) {
            if (mask[j] == 0xFF && data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return base + i;
    }
    return 0;
}

void __fastcall DetourRenderLevel(LevelRenderer* levelRenderer, void* screenContext, void* unk) {
    uintptr_t originalAddr = g_originalRenderLevel.load(std::memory_order_relaxed);
    if (originalAddr != 0) {
        auto original = reinterpret_cast<void(__fastcall*)(LevelRenderer*, void*, void*)>(originalAddr);
        original(levelRenderer, screenContext, unk);

        if (levelRenderer && levelRenderer->player) {
            bool isCPressed = (GetAsyncKeyState('C') & 0x8000) != 0;
            float target = isCPressed ? TARGET_ZOOM : 1.0f;

            g_zoomModifier = g_zoomModifier + (target - g_zoomModifier) * 0.1f;

            levelRenderer->player->fov_x *= g_zoomModifier;
            levelRenderer->player->fov_y *= g_zoomModifier;
        }
    }
}

void Initialize() {
    if (MH_Initialize() != MH_OK) return;

    HMODULE base = GetModuleHandleA(nullptr);
    if (!base) return;

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(base) + dosHeader->e_lfanew);
    size_t sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

    uintptr_t callAddr = FindPattern(
            reinterpret_cast<uintptr_t>(base), sizeOfImage,
            RENDER_LEVEL_CALL_SIG, RENDER_LEVEL_CALL_MASK, sizeof(RENDER_LEVEL_CALL_SIG)
    );

    if (callAddr) {
        int32_t offset = *reinterpret_cast<int32_t*>(callAddr + 1);
        uintptr_t targetAddr = callAddr + 5 + offset;

        void* original = nullptr;
        if (MH_CreateHook(reinterpret_cast<void*>(targetAddr), &DetourRenderLevel, &original) == MH_OK) {
            g_originalRenderLevel.store(reinterpret_cast<uintptr_t>(original), std::memory_order_relaxed);
            MH_EnableHook(reinterpret_cast<void*>(targetAddr));
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
if (reason == DLL_PROCESS_ATTACH) {
DisableThreadLibraryCalls(hModule);
std::thread(Initialize).detach();
}
return TRUE;
}
