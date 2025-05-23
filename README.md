<h1 align="center">vpr-deviate</h1>
<p align="center">
  <img src="https://img.shields.io/badge/Windows--C--x86-supported-green">
  <img src="https://img.shields.io/badge/Windows--C--x86__64-supported-green">
  <img src="https://img.shields.io/badge/Windows--C++--x86-supported-green">
  <img src="https://img.shields.io/badge/Windows--C++--x86__64-supported-green">
  <img src="https://img.shields.io/badge/MinGW-supported-green">
  <img src="https://img.shields.io/badge/clang-supported-green">
  <img src="https://img.shields.io/badge/MSVC-unsupported-red">
  <a href="https://mit-license.org/">
    <img src="https://img.shields.io/github/license/0xvpr/vpr-deviate?style=flat-square">
  </a>
</p>
A Function hooking/detouring header-only library for Windows (MinGW)

## Table of Contents
- [Example Usage](#example-usage)
- [Integration](#integration)
- [Compilation](#compilation)

### Example Usage
C++
```cpp
#include <vpr/deviate.hpp>
#include <stdio.h>

void target(int x) {
    fprintf(stdout, "%d\n", x);
}

int main() {
    unsigned char original_bytes[_rel_jmp_size_];

    target(5); // 5 - original
    vpr::deviate::detour( target,
                          [](int x) { return x*x; },
                          original_bytes,
                          sizeof(original_bytes) );
    target(5); // 25 - detoured
```
C
```c
#include <vpr/deviate.h>
#include <stdio.h>

void target(int x) {
    fprintf(stdout, "%d\n", x);
}

void func(int x) {
    fprintf(stdout, "%d\n", x*x);
}

int main() {
    target(5); // 5 - original
    vpr_deviate_detour((void *)target, (void *)func, nullptr, 0);
    target(5); // 25 - detoured

    return 0;
}
```

## Integration
### System-wide installation using CMake
```bash                                                        
git clone https://github.com/0xvpr/vpr-deviate.git         
cd vpr-deviate                                             
cmake -DCMAKE_INSTALL_PREFIX=/your/desired/path/ -B build      
cmake --install build                                          
```                                                            
                                                               
### Local installation (fetch directly from github)            
```cmake                                                       
#set( CMAKE_C_STANDARD   99 ) # at least c99 if using c        
#set( CMAKE_CXX_STANDARD 17 ) # at least c++17 if using cpp    
                                                               
include(FetchContent)                                          
FetchContent_Declare(                                          
  vpr-deviate                                              
  GIT_REPOSITORY https://github.com/0xvpr/vpr-deviate.git  
  GIT_TAG main  # Or use a specific version tag like "v1.0.0"  
)                                                              
FetchContent_MakeAvailable(vpr-deviate)                    

add_executable(app main.cpp)
target_link_libraries(app PRIVATE vpr-deviate::deviate)
```

### Compilation
Use GCC or Clang. MSVC won't accept the inline assembly for x64 (will for x86 but it's not supported by the library).
