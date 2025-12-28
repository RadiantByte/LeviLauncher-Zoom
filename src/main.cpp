#include <Windows.h>
#include <cstdint>
#include <atomic>
#include <thread>
#include "MinHook.h"

#pragma pack(push, 1)
struct LevelRendererPlayer {
    uint8_t padding_x[0xF80];
    float fov_x;
    uint8_t padding_y[0xF94 - 0xF80 - 4];
    float fov_y;
};

struct LevelRenderer {
    uint8_t padding[0x3F0];
    LevelRendererPlayer* player;
};
#pragma pack(pop)

static std::atomic<uintptr_t> g_originalRenderLevel{ 0 };
static float g_zoomModifier = 1.0f;
constexpr float TARGET_ZOOM = 10.0f;

constexpr uint8_t RENDER_LEVEL_SIG[] = {
    0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x00, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57, 0x48, 0x8D, 0xA8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0x29, 0x70, 0x00, 0x0F, 0x29, 0x78, 0x00, 0x44, 0x0F, 0x29, 0x40, 0x00, 0x44, 0x0F, 0x29,
    0x48, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x85, 0x00,
    0x00, 0x00, 0x00, 0x4D, 0x8B, 0xE8, 0x4C, 0x8B, 0xE2, 0x4C, 0x8B, 0xF9
};

constexpr uint8_t RENDER_LEVEL_MASK[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF,
    0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
    0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
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

    uintptr_t targetAddr = FindPattern(
        reinterpret_cast<uintptr_t>(base), sizeOfImage,
        RENDER_LEVEL_SIG, RENDER_LEVEL_MASK, sizeof(RENDER_LEVEL_SIG)
    );

    if (targetAddr) {
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
