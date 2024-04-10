#include "vpr/deviate.h"

#include <stdio.h>

unsigned char original_bytes[_rel_jmp_size_];

void* foo_gateway = nullptr;

void foo(int x) {
    fprintf(stdout, "%d\n", x);
}

void bar(int x) {
    fprintf(stdout, "hooked ");

    size_t size = (sizeof(original_bytes)+sizeof(rax_jmp_data_t));
    unsigned char* jump_back = (unsigned char *)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(jump_back, original_bytes, sizeof(original_bytes));

    rax_jmp_data_ptr jmp_data = (rax_jmp_data_ptr)(jump_back+sizeof(original_bytes));
    set_rax_jmp_data(jmp_data, (uint64_t)foo+_rel_jmp_size_);

    ((decltype(&foo))jump_back)(x);
    VirtualFree(jump_back, size, MEM_RELEASE | MEM_FREE);
}

void tramp(int x)
{
    fprintf(stdout, "trampoline %d ", x*2);

    return ((decltype(&foo))foo_gateway)(x);
}

int main() {
    foo(5);

    // C API
    vpr_deviate_detour( (void *)foo,
                        (void *)bar,
                        (void *)original_bytes,
                        sizeof(original_bytes) );
    foo(5);

    // C++ API
    vpr::deviate::detour( foo,
                          [](int x) { printf("%d\n", 5*x); },
                          nullptr,
                          sizeof(original_bytes) );
    foo(5);

    // Restoration
    vpr::deviate::patch( foo,
                         original_bytes,
                         sizeof(original_bytes) );
    foo(5);

    // C++ Interceptor
    auto interceptor = vpr::deviate::interceptor( foo,
                                                  []() { puts("interceptor"); } );
    interceptor.detour();
    foo(5);

    interceptor.restore();
    foo(5);

    auto interceptor2 = vpr::deviate::interceptor( foo,
                                                   tramp );
    foo_gateway = interceptor2.trampoline();
    foo(5);

    interceptor2.restore();
    foo(5);

    return 0;
}
