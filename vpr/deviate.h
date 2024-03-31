/**
 * Created by:      VPR (0xvpr)
 * Created:         March 28th, 2024
 *
 * Updated by:      VPR (0xvpr)
 * Updated:         March 28th, 2024
 *
 * Description:     C99/C++20 Header only library for memory management in Windows.
 *
 * License:         MIT (c) VPR 2024
**/


#ifndef    VPR_DEVIATE_HEADER
#define    VPR_DEVIATE_HEADER



#ifndef    VC_EXTRA_LEAN
#define    VC_EXTRA_LEAN
#endif  // VC_EXTRA_LEAN
#include   <winternl.h>
#include   <windows.h>
#include   <winnt.h>
#include   <intrin.h>



#if        !defined(__cplusplus)
#include   <stdbool.h>
#include   <stdint.h>
#include   <string.h>
#else   // defined(__cplusplus)
#include   <memory>
#include   <cstring>
#include   <cstdint>
#endif  // defined(__cplusplus)



#if        !defined(__cplusplus)
#define             rel_jmp      ( ((uint8_t)0xE9) )
#define             rel_jmp_size ( ((sizeof(uint32_t)+1)) )
#define             mov_rax      ( (((uint16_t)(0x1234)) & 0xFF) == 0x34 ? 0xB848 : 0x48B8 )
#define             jmp_rax      ( (((uint16_t)(0x1234)) & 0xFF) == 0x34 ? 0xE0FF : 0xFFE0 )
#define             jmp_rax_size ( (sizeof(uint16_t)) )
#else   // defined(__cplusplus)
constexpr uint8_t   rel_jmp      = (uint8_t)0xE9;
constexpr uint32_t  rel_jmp_size = ((sizeof(uint32_t)+1));
constexpr uint16_t  mov_rax      = (((uint16_t)0x1234) & 0xFF) == 0x34 ? 0xB848 : 0x48B8;
constexpr uint16_t  jmp_rax      = (((uint16_t)0x1234) & 0xFF) == 0x34 ? 0xE0FF : 0xFFE0;
constexpr size_t    jmp_rax_size = (sizeof(uint16_t));
#endif  // defined(__cplusplus)



////////////////////////////////////////////////////////////////////////////////
//                                 C API
////////////////////////////////////////////////////////////////////////////////



typedef struct __attribute__((packed)) eax_jmp_data {
    uint16_t    mov_eax     : 16;
    uint32_t    address     : 32;
    uint16_t    jmp_eax     : 16;
} eax_jmp_data_t, *eax_jmp_data_ptr;

typedef struct __attribute__((packed)) rax_jmp_data {
    uint16_t    mov_rax     : 16;
    uint64_t    address     : 64;
    uint16_t    jmp_rax     : 16;
} rax_jmp_data_t, *rax_jmp_data_ptr;

typedef struct __attribute__((packed)) gateway_data {
    uint8_t     rel_jmp     :  8;
    int32_t     address     : 32;
} gateway_data_t, *gateway_data_ptr;


__forceinline
void set_rax_jmp_data(rax_jmp_data_ptr jmp_data, uint64_t address) {
    jmp_data->mov_rax = mov_rax;
    jmp_data->address = address+rel_jmp_size; // address after detour patch
    jmp_data->jmp_rax = jmp_rax;
}

__forceinline
void set_gateway_data(gateway_data_ptr gateway_data, int32_t address) {
    gateway_data->rel_jmp = rel_jmp;
    gateway_data->address = address; // address after detour patch
}

/**
 * TODO
**/
__forceinline
bool vpr_deviate_detour(
    uintptr_t       target_addr,
    uintptr_t       detour_addr,
    uintptr_t       original_bytes,
    size_t          original_bytes_size
)
{
    if (original_bytes_size < rel_jmp_size) {
        return false;
    }

    memcpy((void *)original_bytes, (void *)target_addr, original_bytes_size);

    DWORD dwProtect;
    VirtualProtect((void *)target_addr, original_bytes_size, PAGE_EXECUTE_READWRITE, &dwProtect);

    int32_t relative_addr = (int32_t)(detour_addr - target_addr - rel_jmp_size);
    gateway_data_ptr gateway_data = (gateway_data_ptr)(target_addr);
    set_gateway_data(gateway_data, relative_addr);

    VirtualProtect((void *)target_addr, original_bytes_size, dwProtect, &dwProtect);

    return true;
}

/**
 * Hooks into a function and detours the target function to another function, then jumps back.
 *
 * @param:  uintptr_t target_addr
 * @param:  uintptr_t hook_addr
 * @param:  size_t hook_size
 *
 * @return: return address (needs to be freed via VirtualFree by the caller).
**/
__forceinline
uintptr_t vpr_deviate_tramp_hook(
    uintptr_t       target_addr,
    uintptr_t       hook_addr,
    size_t          hook_size,
    uintptr_t       original_bytes,
    size_t          original_bytes_size
)
{
    if (hook_size < rel_jmp_size) {
        return 0;
    }

    uintptr_t gateway = (uintptr_t)VirtualAlloc(NULL, hook_size + rel_jmp_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy((void *)gateway, (void *)target_addr, hook_size);

    int32_t relative_addr = (int32_t)(hook_addr - target_addr - rel_jmp_size);
    gateway_data_ptr gateway_data = (gateway_data_ptr)(gateway + hook_size);
    set_gateway_data(gateway_data, relative_addr);

    if (vpr_deviate_detour(target_addr, hook_addr, original_bytes, original_bytes_size)) {
        return gateway;
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//                                C++ API
////////////////////////////////////////////////////////////////////////////////


#if        defined(__cplusplus)
namespace vpr {
namespace deviate {

/**
 * TODO
**/
__forceinline
bool detour(
    auto&&          target_func,
    auto&&          detour_func,
    auto&&          original_bytes = nullptr,
    size_t          original_bytes_size = 5
)
{
    if (original_bytes_size < rel_jmp_size) {
        return false;
    }

    if (original_bytes) {
        memcpy((void *)original_bytes, (void *)target_func, original_bytes_size);
    }

    DWORD dwProtect;
    VirtualProtect((void *)target_func, original_bytes_size, PAGE_EXECUTE_READWRITE, &dwProtect);

    int32_t relative_func = (int32_t)((uintptr_t)+detour_func - (uintptr_t)target_func - rel_jmp_size);
    gateway_data_ptr gateway_data = (gateway_data_ptr)(target_func);
    set_gateway_data(gateway_data, relative_func);

    VirtualProtect((void *)target_func, original_bytes_size, dwProtect, &dwProtect);

    return true;
}

/**
 * Hooks into a function and detours the target function to another function, then jumps back.
 *
 * @param:  uintptr_t target_addr
 * @param:  uintptr_t hook_addr
 * @param:  size_t hook_size
 *
 * @return: return address (needs to be freed via VirtualFree by the caller).
**/
__forceinline
uintptr_t trampoline(
    auto&&          target_func,
    auto&&          hook_func,
    size_t          hook_size,
    auto&&          original_bytes,
    size_t          original_bytes_size
)
{
    if (hook_size < rel_jmp_size) {
        return 0;
    }

    uintptr_t gateway = (uintptr_t)VirtualAlloc(NULL, hook_size + rel_jmp_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy((void *)gateway, (void *)target_func, hook_size);

    int32_t relative_func = (int32_t)((uintptr_t)+hook_func - (uintptr_t)target_func - rel_jmp_size);
    gateway_data_ptr gateway_data = (gateway_data_ptr)(gateway + hook_size);
    set_gateway_data(gateway_data, relative_func);

    if (detour(target_func, hook_func, original_bytes, original_bytes_size)) {
        return gateway;
    }

    return 0;
}

__forceinline
void restore( auto&& target_func,
              auto&& original_bytes,
              size_t original_bytes_size )
{
    DWORD protect;
    VirtualProtect((void *)target_func, original_bytes_size, PAGE_READWRITE, &protect);
    memcpy((void *)target_func, original_bytes, original_bytes_size);
    VirtualProtect((void *)target_func, original_bytes_size, protect, &protect);
}

} // namespace memory
} // namespace vpr
#endif  // defined(__cplusplus)


#endif  // VPR_DEVIATE_HEADER
