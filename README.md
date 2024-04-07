<h1 align="center">vpr-deviate</h1>
<p align="center">
  <img src="https://img.shields.io/badge/Windows--C--x86-supported-green">
  <img src="https://img.shields.io/badge/Windows--C--x86__64-supported-green">
  <img src="https://img.shields.io/badge/Windows--C++--x86-supported-green">
  <img src="https://img.shields.io/badge/Windows--C++--x86__64-supported-green">
  <a href="https://mit-license.org/">
    <img src="https://img.shields.io/github/license/0xvpr/vpr-shell-shock?style=flat-square">
  </a>
</p>

## Function Hooking/Detouring Header Only Library (Windows)
### Installation
In root directory run the following (or just copy the header from vpr/)
```bash
curl -LSso- https://raw.githubusercontent.com/0xvpr/vpr-toolkit/main/vpr-toolkit | python3 - -p ./include -ivpr-deviate
```

### Example Usage
```cpp
#include <vpr/deviate.h>
#include <stdio.h>

void target(int x) {
    fprintf(stdout, "%d\n", x);
}

void func(int x) {
    fprintf(stdout, "%d\n", x*x);
}

int main() {
    target(5); // 5
    vpr_deviate_detour((void *)target, (void *)func, nullptr, 0);
    target(5); // 25

    return 0;
}
```

### Compilation
Use GCC or Clang. MSVC won't accept the inline assembly for x64.
