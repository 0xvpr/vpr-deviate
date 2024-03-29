#include "vpr/deviate.h"

#include <stdio.h>

void foo() {
    fprintf(stdout, "%s\n", "Testing");
}

int main() {
    foo();
    auto hook = vpr::deviate::hook::make_hook(
        foo,
        [](){
            printf("%s\n", "STOLEN");
        }
    );
    hook.detour();
    foo();

    return 0;
}
