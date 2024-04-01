#include <stdio.h>

int x = 420;
__declspec(dllexport) void foo(void)
{
    x = x == 420 ? 69 : 420;
    fprintf(stdout, "%d", x);
}

int main(void)
{
    while (1) {
        foo();
        getchar();
    }

    return 0;
}
