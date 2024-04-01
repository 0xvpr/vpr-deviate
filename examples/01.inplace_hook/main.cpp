#include "vpr/deviate.h"

#include <stdio.h>

unsigned char original_bytes[rel_jmp_size];

void foo(int x) {
    fprintf(stdout, "%d\n", x);
}

void bar(int x) {
    fprintf(stdout, "hooked ");

    size_t size = (sizeof(original_bytes)+sizeof(rax_jmp_data));
    unsigned char* jump_back = (unsigned char *)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(jump_back, original_bytes, sizeof(original_bytes));

    rax_jmp_data_ptr jmp_data = (rax_jmp_data_ptr)(jump_back+sizeof(original_bytes));
    set_rax_jmp_data(jmp_data, (uint64_t)foo+rel_jmp_size);

    ((decltype(&foo))jump_back)(x);
    VirtualFree(jump_back, size, MEM_RELEASE | MEM_FREE);
}

int main() {
    // C API
    foo(5);
    vpr_deviate_detour( (void *)foo,
                        (void *)bar,
                        (void *)original_bytes,
                        sizeof(original_bytes) );
    // C++ api
    foo(5);
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

    return 0;
}