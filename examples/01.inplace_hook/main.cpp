#include "vpr/deviate.hpp"

#include <cstdio>

unsigned char original_bytes[_rel_jmp_size_];

void* foo_gateway = nullptr;

void foo(int x) {
    fprintf(stdout, "[-] foo(%d) = %d\n", x, x);
}

void bar(int x) {
    fprintf(stdout, "[+] function hooked; bar(%d) = 'whatever your heart desires'; Returning to foo with 3x\n", x);

    size_t size = (sizeof(original_bytes)+sizeof(rax_jmp_data_t));
    unsigned char* jump_back = (unsigned char *)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(jump_back, original_bytes, sizeof(original_bytes));

    rax_jmp_data_ptr jmp_data = (rax_jmp_data_ptr)(jump_back+sizeof(original_bytes));
    set_rax_jmp_data(jmp_data, (uint64_t)foo+_rel_jmp_size_);

    ((decltype(&foo))jump_back)(x*3);
    VirtualFree(jump_back, size, MEM_RELEASE | MEM_FREE);
}

void tramp(int x)
{
    fprintf(stdout, "[+] trampoline hooked foo; foo(%d) = %d; Returning to foo:\n", x, x*2);

    return ((decltype(&foo))foo_gateway)(x);
}

int main() {
    fprintf(stdout, "Legend: [-] Normal function call | [+] Detoured function call | [!] Deviate library action\n\n");
    foo(5);

    // C++ API
    fprintf(stdout, "[!] foo lambda detoured\n");
    vpr::deviate::detour( foo,
                          [](int x) { printf("[+] lambda detour foo(%d) = %d\n", x, 5*x); },
                          original_bytes,
                          sizeof(original_bytes) );
    foo(5);

    // Restoration
    fprintf(stdout, "[!] foo(%d) patched to original function\n", 5);
    vpr::deviate::patch( foo,
                         original_bytes,
                         sizeof(original_bytes) );
    foo(5);

    // C++ Interceptor
    auto interceptor = vpr::deviate::interceptor( foo,
                                                  [](int x) { fprintf(stdout, "[+] interceptor foo(%d) = 'All your base are belong to us'\n", x); } );
    fprintf(stdout, "[!] interceptor object created with lambda\n");
    interceptor.detour();
    foo(5);

    interceptor.restore();
    fprintf(stdout, "[!] foo(%d) restored\n", 5);
    foo(5);

    // Tramp hook
    {
        auto intc = vpr::deviate::interceptor( foo,
                                               tramp );
        fprintf(stdout, "[!] interceptor context created\n");

        foo_gateway = intc.trampoline();
        foo(5);
    }
    fprintf(stdout, "[!] interceptor context destroyed\n");

    // Bar detour
    {
        auto intc = vpr::deviate::interceptor( foo,
                                               bar );
        fprintf(stdout, "[!] interceptor context created\n");

        intc.detour();
        foo(5);
    }
    fprintf(stdout, "[!] interceptor context destroyed\n");

    foo(5);

    return 0;
}
