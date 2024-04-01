/**
 * Created by:      VPR (0xvpr)
 * Created:         March 28th, 2024
 *
 * Updated by:      VPR (0xvpr)
 * Updated:         April 1st, 2024
 *
 * Description:     C99/C++20 Header only library for memory management in Windows.
 *
 * License:         MIT (c) VPR 2024
**/


#ifndef    VPR_DEVIATE_HEADER
#define    VPR_DEVIATE_HEADER



#include <memoryapi.h>
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
    jmp_data->address = address;
    jmp_data->jmp_rax = jmp_rax;
}

__forceinline
void set_gateway_data(gateway_data_ptr gateway_data, int32_t address) {
    gateway_data->rel_jmp = rel_jmp;
    gateway_data->address = address;
}



/**
 * TODO
**/
__forceinline
uintptr_t vpr_deviate_resolve_dynamic_address(
    uintptr_t       address,
    uint16_t*       offsets,
    size_t          size
) { 
    for (size_t i = 0; i < size; i++) {
        if (!address) {
            return 0;
        }

        address = *(uintptr_t *)address;
        address += offsets[i];

        if (!address || *(uintptr_t *)address == 0) {
            return 0;
        }
    }

    return address;
}

/**
 * TODO
**/
__forceinline
bool vpr_deviate_patch(
    uintptr_t       destination,
    uintptr_t       source,
    size_t          size
) {
    DWORD protect;
    if (!VirtualProtect((void *)destination, size, PAGE_EXECUTE_READWRITE, &protect)) {
        return false;
    }

    memcpy((void *)destination, (void *)source, size);

    if (!VirtualProtect((void *)destination, size, protect, &protect)) {
        return false;
    }

    return true;
}

/**
 * Detours the target to another function.
 *
 * @param: uintptr_t  target_func,
 * @param: uintptr_t  detour_func,
 * @param: uintptr_t  original_bytes,
 * @param: size_t     original_bytes_size
 *
 * @return: success
**/
__forceinline
bool vpr_deviate_detour(
    uintptr_t       target_func,
    uintptr_t       detour_func,
    uintptr_t       original_bytes,
    size_t          original_bytes_size
) {
    if (original_bytes) {
        memcpy((void *)original_bytes, (void *)target_func, original_bytes_size);
    }

    DWORD protect;
    uint64_t relative_func = detour_func - target_func - rel_jmp_size;
    if ((relative_func & 0xFFFFFFFF00000000)) {
        VirtualProtect((void *)target_func, sizeof(rax_jmp_data), PAGE_EXECUTE_READWRITE, &protect);
        rax_jmp_data_ptr jmp_data = (rax_jmp_data_ptr)(target_func);
        set_rax_jmp_data(jmp_data, (uintptr_t)detour_func);
        VirtualProtect((void *)target_func, sizeof(rax_jmp_data), protect, &protect);
    } else {
        VirtualProtect((void *)target_func, sizeof(rel_jmp_size), PAGE_EXECUTE_READWRITE, &protect);
        gateway_data_ptr gateway_data = (gateway_data_ptr)(target_func);
        set_gateway_data(gateway_data, (int32_t)relative_func);
        VirtualProtect((void *)target_func, sizeof(rel_jmp_size), protect, &protect);
    }

    return true;
}

/**
 * Detours the target to another function then returns a gateway address to the original target.
 *
 * @param: uintptr_t  target_func,
 * @param: uintptr_t  detour_func,
 * @param: size_t     detour_size,
 * @param: uintptr_t  original_bytes,
 * @param: size_t     original_bytes_size
 *
 * @return: uintptr_t gateway_address (needs to be freed via VirtualFree by the caller when non-zero).
**/
__forceinline
uintptr_t vpr_deviate_tramp_hook(
    uintptr_t       target_func,
    uintptr_t       detour_func,
    size_t          detour_size,
    uintptr_t       original_bytes,
    size_t          original_bytes_size
) {
    if (detour_size < rel_jmp_size) {
        return 0;
    }

    uintptr_t gateway = (uintptr_t)VirtualAlloc(NULL, detour_size + rel_jmp_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy((void *)gateway, (void *)target_func, detour_size);

    int32_t relative_addr = (int32_t)(detour_func - target_func - rel_jmp_size);
    gateway_data_ptr gateway_data = (gateway_data_ptr)(gateway + detour_size);
    set_gateway_data(gateway_data, relative_addr);

    if (vpr_deviate_detour(target_func, detour_func, original_bytes, original_bytes_size)) {
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
 * Detours the target to another function.
 *
 * @param: auto&&     target_func,
 * @param: auto&&     detour_func,
 * @param: auto&&     original_bytes,
 * @param: size_t     original_bytes_size
 *
 * @return: success
**/
__forceinline
bool detour(
    auto&&          target_func,
    auto&&          detour_func,
    auto&&          original_bytes = nullptr,
    size_t          original_bytes_size = rel_jmp_size
) {
    if (original_bytes) {
        memcpy((void *)original_bytes, (void *)target_func, original_bytes_size);
    }

    DWORD protect;
    uint64_t relative_func = (uintptr_t)+detour_func - (uintptr_t)target_func - rel_jmp_size;
    if ((relative_func & 0xFFFFFFFF00000000)) {
        VirtualProtect((void *)target_func, sizeof(rax_jmp_data), PAGE_EXECUTE_READWRITE, &protect);
        set_rax_jmp_data(reinterpret_cast<rax_jmp_data_ptr>(target_func), (uintptr_t)+detour_func);
        VirtualProtect((void *)target_func, sizeof(rax_jmp_data), protect, &protect);
    } else {
        VirtualProtect((void *)target_func, sizeof(rel_jmp_size), PAGE_EXECUTE_READWRITE, &protect);
        set_gateway_data(reinterpret_cast<gateway_data_ptr>(target_func), (int32_t)relative_func);
        VirtualProtect((void *)target_func, sizeof(rel_jmp_size), protect, &protect);
    }

    return true;
}

/**
 * Detours the target to another function then returns a gateway address to the original target.
 *
 * @param: auto&&     target_func,
 * @param: auto&&     detour_func,
 * @param: size_t     detour_size,
 * @param: auto&&     original_bytes,
 * @param: size_t     original_bytes_size
 *
 * @return: uintptr_t gateway_address (needs to be freed via VirtualFree by the caller when non-zero).
**/
__forceinline
uintptr_t trampoline(
    auto&&          target_func,
    auto&&          detour_func,
    size_t          detour_size,
    auto&&          original_bytes,
    size_t          original_bytes_size
) {
    if (detour_size < rel_jmp_size) {
        return 0;
    }
    uint64_t relative_func = ((uintptr_t)+detour_func - (uintptr_t)target_func - rel_jmp_size);
    uintptr_t gateway = 0;

    if ((relative_func & 0xFFFFFFFF00000000)) {
        gateway = (uintptr_t)VirtualAlloc(NULL, detour_size+sizeof(rax_jmp_data), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy((void *)gateway, (void *)target_func, detour_size);
        set_rax_jmp_data(reinterpret_cast<rax_jmp_data_ptr>(gateway + detour_size), (uintptr_t)target_func);

        DWORD protect;
        VirtualProtect(reinterpret_cast<void *>(gateway), detour_size+rel_jmp_size, PAGE_EXECUTE_READ, &protect);
    } else {
        gateway = (uintptr_t)VirtualAlloc(NULL, detour_size+rel_jmp_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy((void *)gateway, (void *)target_func, detour_size);
        set_gateway_data(reinterpret_cast<gateway_data_ptr>(gateway+detour_size), (int32_t)relative_func);

        DWORD protect;
        VirtualProtect(reinterpret_cast<void *>(gateway), detour_size+rel_jmp_size, PAGE_EXECUTE_READ, &protect);
    }

    if (detour(target_func, detour_func, original_bytes, original_bytes_size)) {
        return gateway;
    }

    return 0;
}

/**
 * TODO
**/
__forceinline
bool patch(
    auto&&          destination,
    auto&&          source,
    size_t          size
) {
    DWORD protect;
    if (!VirtualProtect((void *)destination, size, PAGE_EXECUTE_READWRITE, &protect)) {
        return false;
    }

    memcpy((void *)destination, (void *)source, size);

    if (!VirtualProtect((void *)destination, size, protect, &protect)) {
        return false;
    }

    return true;
}

} // namespace memory
} // namespace vpr
#endif  // defined(__cplusplus)


#endif  // VPR_DEVIATE_HEADER
