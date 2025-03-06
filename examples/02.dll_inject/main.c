#include <stdio.h>

int x = 420;
__declspec(dllexport) void foo(void)
{
    x = x == 420 ? 69 : 420;
    fprintf(stdout, "%d", x);
}

int main(void)
{
    fprintf(stdout, "Press [return] to alternate between 69 and 420 endlessly.\n", x);
    while (1) {
        foo();
        getchar();
    }

    return 0;
}
