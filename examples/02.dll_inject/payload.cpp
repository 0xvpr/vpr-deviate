#include "vpr/deviate.h"

#include <stdio.h>

void bar() {
    fprintf(stdout, "DETOURED\n");
    exit(1);
}

DWORD WINAPI Main(HINSTANCE instance) {

    auto target = (uintptr_t)GetProcAddress(GetModuleHandleA(nullptr), "foo");
    vpr::deviate::detour( target,
                          bar,
                          nullptr );

    while (true);
    FreeLibraryAndExitThread(instance, 0);
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
    (void)lpReserved;

    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstance);
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Main, hInstance, 0, nullptr);
    }

    return true;
}
