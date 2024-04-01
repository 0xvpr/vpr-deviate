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



#ifndef    VC_EXTRA_LEAN
#define    VC_EXTRA_LEAN
#endif  // VC_EXTRA_LEAN
#include   <windows.h>



#if        !defined(__cplusplus)
#include   <stdbool.h>
#include   <stdint.h>
#include   <string.h>

#else   // defined(__cplusplus)
#include   <cstring>
#include   <cstdint>
#endif  // defined(__cplusplus)
#include   <stdio.h>



#if        !defined(__cplusplus)
#define             rel_jmp      ( ((uint8_t)0xE9) )
#define             rel_jmp_size ( ((sizeof(uint32_t)+1)) )
#define             mov_rax      ( (((uint16_t)(0x1234)) & 0xFF) == 0x34 ? 0xB848 : 0x48B8 )
#define             jmp_rax      ( (((uint16_t)(0x1234)) & 0xFF) == 0x34 ? 0xE0FF : 0xFFE0 )
#define             jmp_rax_size ( (sizeof(uint16_t)) )
#else   // defined(__cplusplus)
constexpr uint8_t   rel_jmp      = (uint8_t)0xE9;
constexpr uint32_t  rel_jmp_size = ((sizeof(uint32_t)+1));
constexpr uint16_t  mov_rax      = (((uint16_t)(0x1234)) & 0xFF) == 0x34 ? 0xB848 : 0x48B8;
constexpr uint16_t  jmp_rax      = (((uint16_t)(0x1234)) & 0xFF) == 0x34 ? 0xE0FF : 0xFFE0;
constexpr size_t    jmp_rax_size = (sizeof(uint16_t));
#endif  // defined(__cplusplus)



////////////////////////////////////////////////////////////////////////////////
//                                 C API
////////////////////////////////////////////////////////////////////////////////


typedef BOOL (WINAPI * VirtualProtect_t)( LPVOID lpAddress,
                                          SIZE_T dwSize,
                                          DWORD flNewProtect,
                                          PDWORD lpflOldProtect );

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

typedef struct __attribute__((packed)) rel_jmp_data {
    uint8_t     rel_jmp     :  8;
    int32_t     address     : 32;
} rel_jmp_data_t, *rel_jmp_data_ptr;



__forceinline
void set_rax_jmp_data(rax_jmp_data_ptr jmp_data, uint64_t address) {
    jmp_data->mov_rax = mov_rax;
    jmp_data->address = address;
    jmp_data->jmp_rax = jmp_rax;
}

__forceinline
void set_rel_jmp_data(rel_jmp_data_ptr rel_jmp_data, int32_t address) {
    rel_jmp_data->rel_jmp = rel_jmp;
    rel_jmp_data->address = address;
}



/**
 * Resolve dynamic address using address and pointer array.
 *
 * @param:  uintptr_t       address
 * @param:  const uint16_t* offsets
 * @param:  const size_t    n_memb
 *
 * @return: uintptr_t       resolved_address
**/
__forceinline
uintptr_t vpr_deviate_resolve_dynamic_address( uintptr_t       address,
                                               const uint16_t* offsets,
                                               const size_t    n_memb )
{ 
    for (size_t i = 0; i < n_memb; i++) {
        if (!address) {
            return 0;
        }

        address = *(uintptr_t *)address;
        address += offsets[i];

        if (*(uintptr_t *)address == 0) {
            return 0;
        }
    }

    return address;
}

/**
 * Replace executable of destination from the source.
 *
 * @param:  void*           destination,
 * @param:  const void*     source,
 * @param:  const size_t    size
 *
 * @return: bool            success
**/
__forceinline
bool vpr_deviate_patch( void*        destination,
                        const void*  source,
                        const size_t size )
{
    DWORD protect;
    if (!VirtualProtect(destination, size, PAGE_EXECUTE_READWRITE, &protect)) {
        return false;
    }

    memcpy(destination, source, size);

    if (!VirtualProtect(destination, size, protect, &protect)) {
        return false;
    }

    return true;
}

/**
 * Detours the target to another function.
 *
 * @param:  void*            target_func,
 * @param:  const void*      detour_func,
 * @param:  void*            original_bytes,
 * @param:  const size_t     original_bytes_size
 *
 * @return: uint64_t         success
**/
__forceinline
uint64_t vpr_deviate_detour( void*        target_func,
                             const void*  detour_func,
                             void*        original_bytes,
                             const size_t original_bytes_size )
{
    if (original_bytes) {
        memcpy(original_bytes, target_func, original_bytes_size);
    }

    DWORD protect;
    uint64_t relative_func = (uintptr_t)detour_func - (uintptr_t)target_func - rel_jmp_size;
    if ((relative_func & 0xFFFFFFFF00000000)) {
        VirtualProtect(target_func, sizeof(rax_jmp_data), PAGE_EXECUTE_READWRITE, &protect);
        set_rax_jmp_data((rax_jmp_data_ptr)target_func, (uintptr_t)detour_func);
        VirtualProtect(target_func, sizeof(rax_jmp_data), protect, &protect);

        return sizeof(rax_jmp_data);
    }

    VirtualProtect(target_func, sizeof(rel_jmp_size), PAGE_EXECUTE_READWRITE, &protect);
    set_rel_jmp_data((rel_jmp_data_ptr)target_func, (int32_t)relative_func);
    VirtualProtect(target_func, sizeof(rel_jmp_size), protect, &protect);

    return sizeof(rel_jmp_data);
}

/**
 * Detours the target to another function.
 *
 * @param:  void*            target_func,
 * @param:  const void*      detour_func,
 * @param:  void*            original_bytes,
 * @param:  const size_t     original_bytes_size
 *
 * @return: bool            success
**/
__forceinline
uint64_t vpr_deviate_detour_ex( void*            target_func,
                                const void*      detour_func,
                                void*            original_bytes,
                                const size_t     original_bytes_size,
                                VirtualProtect_t fVirtualProtect )
{
    if (!fVirtualProtect) {
        return 0;
    }

    if (original_bytes) {
        for (size_t i = 0; i < original_bytes_size; ++i) ((char *)original_bytes)[i] = ((char *)target_func)[i];
    }

    DWORD protect;
    uint64_t relative_func = (uintptr_t)detour_func - (uintptr_t)target_func - rel_jmp_size;
    if ((relative_func & 0xFFFFFFFF00000000)) {
        fVirtualProtect(target_func, sizeof(rax_jmp_data), PAGE_EXECUTE_READWRITE, &protect);
        set_rax_jmp_data((rax_jmp_data_ptr)target_func, (uintptr_t)detour_func);
        fVirtualProtect(target_func, sizeof(rax_jmp_data), protect, &protect);

        return sizeof(rax_jmp_data);
    }

    fVirtualProtect(target_func, sizeof(rel_jmp_size), PAGE_EXECUTE_READWRITE, &protect);
    set_rel_jmp_data((rel_jmp_data_ptr)target_func, (int32_t)relative_func);
    fVirtualProtect(target_func, sizeof(rel_jmp_size), protect, &protect);

    return sizeof(rel_jmp_data);
}

/**
 * Detours the target to another function then returns a gateway address to the original target.
 *
 * @param:  void*           target_func,
 * @param:  const void*     detour_func,
 * @param:  size_t          detour_size,
 * @param:  void*           original_bytes,
 * @param:  size_t          original_bytes_size
 *
 * @return: void*           gateway_address (needs to be freed via VirtualFree by the caller when non-zero)
**/
__forceinline
void* vpr_deviate_trampoline( void*       target_func,
                              const void* detour_func,
                              size_t      detour_size,
                              void*       original_bytes,
                              size_t      original_bytes_size )
{
    if (detour_size < rel_jmp_size) {
        return NULL;
    }

    void* gateway;
    if (!(gateway = VirtualAlloc(NULL, detour_size + rel_jmp_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))) {
        return NULL;
    }
    memcpy((void *)gateway, (void *)target_func, detour_size);

    int32_t relative_addr = (int32_t)((uintptr_t)detour_func - (uintptr_t)target_func - rel_jmp_size);
    rel_jmp_data_ptr rel_jmp_data = (rel_jmp_data_ptr)((uintptr_t)gateway + detour_size);
    set_rel_jmp_data(rel_jmp_data, relative_addr);

    if (vpr_deviate_detour(target_func, detour_func, original_bytes, original_bytes_size)) {
        return gateway;
    }

    return NULL;
}


////////////////////////////////////////////////////////////////////////////////
//                                C++ API
////////////////////////////////////////////////////////////////////////////////


#if        defined(__cplusplus)
namespace vpr {
namespace deviate {

/**
 * Resolve dynamic address using address and pointer array.
 *
 * @param:  uintptr_t       address
 * @param:  const uint16_t* offsets
 * @param:  const size_t    n_memb
 *
 * @return: uintptr_t       resolved_address
**/
__forceinline
uintptr_t resolve_dynamic_address( uintptr_t       address,
                                   const uint16_t* offsets,
                                   const size_t    n_memb )
{ 
    return vpr_deviate_resolve_dynamic_address( address,
                                                offsets,
                                                n_memb );
}

/**
 * Replace executable of destination from the source.
 *
 * @param:  auto&&          destination
 * @param:  auto&&          source
 * @param:  const size_t    n_bytes
 *
 * @return: bool            success
**/
__forceinline
bool patch( auto&&       destination,
            auto&&       source,
            const size_t size )
{
    return vpr_deviate_patch( (void *)+destination,
                              (const void *)+source,
                              size );
}

/**
 * Detours the target to another function.
 *
 * @param:  auto&&          target_func
 * @param:  auto&&          detour_func
 * @param:  auto&&          original_bytes
 * @param:  const size_t    original_bytes_size
 *
 * @return: uint64_t         success
**/
__forceinline
uint64_t detour( auto&&       target_func,
                 auto&&       detour_func,
                 auto&&       original_bytes = nullptr,
                 const size_t original_bytes_size = rel_jmp_size )
{
    return vpr_deviate_detour( (void *)+target_func,
                               (const void *)+detour_func,
                               original_bytes,
                               original_bytes_size );
}

/**
 * Detours the target to another function then returns a gateway address to the original target.
 *
 * @param:  auto&&          target_func
 * @param:  auto&&          detour_func
 * @param:  size_t          detour_size
 * @param:  auto&&          original_bytes
 * @param:  size_t          original_bytes_size
 *
 * @return: void*           gateway_address (needs to be freed via VirtualFree by the caller when non-zero)
**/
__forceinline
void* trampoline( auto&&       target_func,
                  auto&&       detour_func,
                  const size_t detour_size,
                  auto&&       original_bytes = nullptr,
                  const size_t original_bytes_size = rel_jmp_size )
{
    return vpr_deviate_trampoline( (void *)+target_func,
                                   (const void *)+detour_func,
                                   detour_size,
                                   original_bytes,
                                   original_bytes_size );

}

////////////////////////////////////////////////////////////////////////////////
//                               Hook Manager
////////////////////////////////////////////////////////////////////////////////

class [[nodiscard]] interceptor {
public:
    interceptor() = delete;
    interceptor(const interceptor &) = delete;
    interceptor& operator = (const interceptor &) = delete;
    interceptor(interceptor&&) = delete;
    interceptor& operator = (interceptor &&) = delete;

    __forceinline
    explicit constexpr interceptor( auto&& target_func,
                                    auto&& detour_func )
    : target_func_((uintptr_t)+target_func)
    , detour_func_((uintptr_t)+detour_func)
    , original_data_(*((original_data_ptr)(target_func_)))
    {
    }

    __forceinline
    uint64_t relative_addr() const {
        return detour_func_ - target_func_ - rel_jmp_size;
    }

    __forceinline
    uint64_t detour() const {
        return vpr::deviate::detour( target_func_,
                                     detour_func_,
                                     nullptr );
    }

    __forceinline
    uint64_t detour( auto&&       original_bytes = nullptr,
                     const size_t original_bytes_size = rel_jmp_size ) const
    {
        return vpr::deviate::detour( target_func_,
                                     detour_func_,
                                     original_bytes,
                                     original_bytes_size );
    }

    /*__forceinline*/
    /*uint64_t detour(VirtualProtect_t fVirtualProtect) {*/
        /*return vpr_deviate_detour_ex(target_func_, detour_func_)*/
    /*}*/

    __forceinline
    bool restore() const {
        return vpr::deviate::patch( target_func_,
                                    &original_data_,
                                    relative_addr() < 0x100000000 ?
                                        sizeof(rel_jmp_data)    :
                                        sizeof(rax_jmp_data));
    }

    __forceinline
    uintptr_t trampoline(
                  const size_t detour_size,
                  auto&&       original_bytes = nullptr,
                  const size_t original_bytes_size = rel_jmp_size ) const
    {
        return vpr::deviate::trampoline( target_func_,
                                         detour_func_,
                                         detour_size,
                                         original_bytes,
                                         original_bytes_size );
    }

private:
    typedef struct {
        union {
            rax_jmp_data rax_jmp_data_;
            rel_jmp_data rel_jmp_data_;
        };
    } original_data, *original_data_ptr;

    uintptr_t           target_func_;
    uintptr_t           detour_func_;
    const original_data original_data_;
}; // class interceptor

} // namespace memory
} // namespace vpr
#endif  // defined(__cplusplus)


#endif  // VPR_DEVIATE_HEADER
