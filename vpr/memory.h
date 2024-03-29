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


#ifndef    VPR_MEMORY_HEADER
#define    VPR_MEMORY_HEADER


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
#include   <cstring>
#include   <cstdint>
#endif  // defined(__cplusplus)


////////////////////////////////////////////////////////////////////////////////
//                                 C API
////////////////////////////////////////////////////////////////////////////////


DWORD vm_get_process_id_by_process_name(LPCSTR process_name);
VOID  vm_get_process_name_by_process_id(DWORD process_id, LPCSTR buffer, SIZE_T size);

VOID  vm_safe_zero_memory(LPVOID addr);
VOID  vm_safe_set_memory(LPVOID addr);

VOID  vm_unsafe_fast_set_memory_64(LPVOID addr);
VOID  vm_unsafe_fast_set_memory_128(LPVOID addr);
VOID  vm_unsafe_fast_set_memory_256(LPVOID addr);
VOID  vm_unsafe_fast_set_memory_512(LPVOID addr);
VOID  vm_unsafe_fast_set_memory_1024(LPVOID addr);
VOID  vm_unsafe_fast_set_memory_2048(LPVOID addr);
VOID  vm_unsafe_fast_set_memory_4096(LPVOID addr);
VOID  vm_unsafe_fast_set_memory_8192(LPVOID addr);
VOID  vm_unsafe_fast_copy_memory_64(LPVOID addr);
VOID  vm_unsafe_fast_copy_memory_128(LPVOID addr);
VOID  vm_unsafe_fast_copy_memory_256(LPVOID addr);
VOID  vm_unsafe_fast_copy_memory_512(LPVOID addr);
VOID  vm_unsafe_fast_copy_memory_1024(LPVOID addr);
VOID  vm_unsafe_fast_copy_memory_2048(LPVOID addr);
VOID  vm_unsafe_fast_copy_memory_4096(LPVOID addr);
VOID  vm_unsafe_fast_copy_memory_8192(LPVOID addr);
VOID  vm_unsafe_fast_zero_memory_64(LPVOID addr);
VOID  vm_unsafe_fast_zero_memory_128(LPVOID addr);
VOID  vm_unsafe_fast_zero_memory_256(LPVOID addr);
VOID  vm_unsafe_fast_zero_memory_512(LPVOID addr);
VOID  vm_unsafe_fast_zero_memory_1024(LPVOID addr);
VOID  vm_unsafe_fast_zero_memory_2048(LPVOID addr);
VOID  vm_unsafe_fast_zero_memory_4096(LPVOID addr);
VOID  vm_unsafe_fast_zero_memory_8192(LPVOID addr);

/**
 * Finds the Dynamic Memory Access address of an embedded process.
 *
 * @param:  UINT_PTR ptr
 * @param:  unsigned offsets[]
 * @param:  SIZE_T size
 *
 * @return: UINT_PTR
**/
__forceinline
BOOL vm_memory_find_dynamic_address(UINT_PTR address, LPVOID offsets, SIZE_T n_memb, SIZE_T size);

/**
 * Finds the Dynamic Memory Access address in a remote process.
 *
 * @param:  UINT_PTR ptr
 * @param:  unsigned offsets[]
 * @param:  SIZE_T size
 *
 * @return: UINT_PTR
**/
__forceinline
BOOL vm_memory_find_dynamic_address(HANDLE process_handle, UINT_PTR address, LPVOID offsets, SIZE_T n_memb, SIZE_T size);

/**
 * Byte replacement from source to destination.
 *
 * @param:  void destination
 * @param:  void source
 * @param:  SIZE_T size
 *
 * @return: void
**/
__forceinline
BOOL vm_memory_patch(UINT_PTR dst, UINT_PTR src, SIZE_T size);

/**
 * Byte replacement from source to destination in a remote process.
 *
 * @param:  void destination
 * @param:  void source
 * @param:  SIZE_T size
 *
 * @return: void
**/
__forceinline
BOOL vm_memory_patch_ex(HANDLE process_handle, UINT_PTR dst, UINT_PTR src, SIZE_T size);

/**
 * Hooks into a function and detours the target function to another function.
 *
 * @param:  LPVOID targetFunc
 * @param:  LPVOID myFunc
 * @param:  SIZE_T size
 *
 * @return: BOOL
**/
__forceinline
BOOL vm_memory_detour(UINT_PTR target_addr, UINT_PTR detour_addr, SIZE_T detour_size);

/**
 * Hooks into a function and detours the target function to another function.
 *
 * @param:  LPVOID targetFunc
 * @param:  LPVOID myFunc
 * @param:  SIZE_T size
 *
 * @return: BOOL
**/
__forceinline
BOOL vm_memory_detour(UINT_PTR target_addr, UINT_PTR detour_addr, SIZE_T detour_size);

/**
 * Hooks into a function and detours the target function to another function, then jumps back.
 *
 * @param:  LPVOID src
 * @param:  LPVOID dst
 * @param:  SIZE_T size
 *
 * @return: char*
**/
__forceinline
UINT_PTR vm_memory_tramp_hook(UINT_PTR target_addr, UINT_PTR hook_addr, SIZE_T hook_size);

/**
 * Scans a given chunk of data for the given pattern and mask.
 *
 * @param:  base_addr       The base address of where the scan data is from.
 * @param:  img_size        The size of the module.
 * @param:  pattern         The pattern to scan for.
 * @param:  pattern_size    The size of the pattern to scan for.
 *
 * @return: Pointer of the pattern found, 0 otherwise.
**/
__forceinline
UINT_PTR vm_memory_find_pattern(UINT_PTR base_addr, SIZE_T img_size, PBYTE pattern, SIZE_T pattern_size);


////////////////////////////////////////////////////////////////////////////////
//                                C++ API
////////////////////////////////////////////////////////////////////////////////


#if        defined(__cplusplus)
namespace vpr {
namespace memory {

class hook {
public:
    hook() = delete;
    hook(const hook& other) = delete;
    hook& operator = (const hook& other) = delete;
private:
    explicit hook(UINT_PTR original_addr, UINT_PTR hook_addr);

    UINT_PTR original_addr;
    UINT_PTR hook_addr;
};

class model {
public:
    model() = delete;
    model(const model&) = delete;
    model& operator = (const model&) = delete;

    //   Initialization and Cleanup
    //       InitializeLibrary: Prepares any necessary internal structures, checks for necessary permissions, etc.
    //       CleanupLibrary: Frees resources, closes handles, etc., before the library is unloaded.
    //
    //   Process Selection and Management
    //       AttachToProcess: Attaches to a target process using its PID (Process ID) or name, to perform memory operations.
    //       DetachFromProcess: Detaches from the currently attached process.
    //
    //   Memory Reading and Writing
    //       ReadMemory: Reads memory from the target process into a local buffer.
    //       WriteMemory: Writes data from a local buffer to a specific location in the target process's memory.
    //
    //   Memory Allocation and Deallocation
    //       AllocateMemory: Allocates memory within the virtual address space of the target process.
    //       FreeMemory: Frees previously allocated memory within the target process.
    //
    //   Memory Protection
    //       ChangeMemoryProtection: Changes the protection on a region of memory in the target process, e.g., to make a read-only region writable.
    //
    //   Memory Searching and Pattern Matching
    //       FindPattern: Searches the process's memory for a specific pattern or signature, which can be useful for finding offsets or data structures dynamically.
    //
    //   Debugging and Information
    //       GetMemoryInfo: Retrieves information about a specific region of memory in the target process, such as its protection status, type, and size.
    //       LogError: Provides logging for errors encountered by the library functions.
    //
    //   Module and Address Resolution
    //       GetModuleBaseAddress: Retrieves the base address of a given module loaded within the target process, useful for calculating offsets.
    //       ResolveAddress: Resolves an address based on a given module and offset, simplifying the process of finding specific functions or data structures.
    //   Hooking and Detouring struct/class
private:
};

} // namespace memory
} // namespace vpr
#endif  // defined(__cplusplus)


#endif  // VPR_MEMORY_HEADER
