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
#define             mov_rax ( (((uint16_t)(0x1234)) & 0xFF) == 0x34 ? 0xB848 : 0x48B8)
#define             jmp_rax ( (((uint16_t)(0x1234)) & 0xFF) == 0x34 ? 0xE0FF : 0xFFE0)
#define             abs_jmp_rax_size ( ((sizeof(uint16_t)) + sizeof(uint64_t) + sizeof(uint16_t)) )
#else   // defined(__cplusplus)
constexpr uint16_t  mov_rax = ((uint16_t)0x1234 & 0xFF) == 0x34 ? 0xB848 : 0x48B8;
constexpr uint16_t  jmp_rax = ((uint16_t)0x1234 & 0xFF) == 0x34 ? 0xE0FF : 0xFFE0;
constexpr size_t    abs_jmp_rax_size = sizeof(mov_rax) + sizeof(uint64_t) + sizeof(jmp_rax);
#endif  // defined(__cplusplus)



////////////////////////////////////////////////////////////////////////////////
//                                 C API
////////////////////////////////////////////////////////////////////////////////



typedef struct __attribute__((packed)) asm_block_32 {
    uint16_t    mov_eax;
    uint32_t    address;
    uint16_t    jmp_eax;
} asm_block_32_t, *asm_block_32_ptr;

typedef struct __attribute__((packed)) asm_block_64 {
    uint16_t    mov_rax;
    uint64_t    address;
    uint16_t    jmp_rax;
} asm_block_64_t, *asm_block_64_ptr;



/**
 * TODO
**/
__forceinline
bool vpr_deviate_detour(
    uintptr_t        target_addr,
    uintptr_t        detour_addr,
    size_t           detour_size
);

/**
 * Hooks into a function and detours the target function to another function, then jumps back.
 *
 * @param:  LPVOID src
 * @param:  LPVOID dst
 * @param:  size_t size
 *
 * @return: uintptr_t
**/
__forceinline
uintptr_t vpr_deviate_tramp_hook(
    uintptr_t        target_addr,
    uintptr_t        hook_addr,
    size_t           hook_size
);

////////////////////////////////////////////////////////////////////////////////
//                                C++ API
////////////////////////////////////////////////////////////////////////////////


#if        defined(__cplusplus)
namespace vpr {
namespace deviate {

class hook {
    /*typedef  VirtualProtect_t;*/
public:
    hook() = delete;
    hook(const hook& other) = delete;
    hook& operator = (const hook& other) = delete;

    static inline hook make_hook(auto original_addr, auto hook_addr) {
        return hook(original_addr, hook_addr);
    }

    void detour() {
        DWORD dwProtect = 0;
        VirtualProtect((void *)original_addr_, abs_jmp_rax_size, PAGE_EXECUTE_READWRITE, &dwProtect);
        hook_block_->mov_rax = mov_rax;
        hook_block_->address = hook_addr_;
        hook_block_->jmp_rax = jmp_rax;
        VirtualProtect((void *)original_addr_, abs_jmp_rax_size, dwProtect, &dwProtect);

        is_hooked_ = true;
    }

    void detour(auto&& funcptr) {
        if (!funcptr) return;

        DWORD dwProtect = 0;
        VirtualProtect((void *)original_addr_, abs_jmp_rax_size, PAGE_EXECUTE_READWRITE, &dwProtect);
        hook_block_->mov_rax = mov_rax;
        hook_block_->address = (uint64_t)(+funcptr);
        hook_block_->jmp_rax = jmp_rax;
        VirtualProtect((void *)original_addr_, abs_jmp_rax_size, dwProtect, &dwProtect);

        is_hooked_ = true;
    }

    void restore() {
        if (!is_hooked_) return;

        DWORD dwProtect = 0;
        VirtualProtect((LPVOID)original_addr_, abs_jmp_rax_size, PAGE_EXECUTE_READWRITE, &dwProtect);
        *(asm_block_64_ptr)original_addr_ = restore_block_;
        VirtualProtect((LPVOID)original_addr_, abs_jmp_rax_size, dwProtect, &dwProtect);

        hook_addr_ = 0;
        is_hooked_ = false;
    }

private:
    explicit constexpr hook(auto&& original_addr, auto&& hook_addr) //, auto&& fVirtualProtect = VirtualProtect)
        : original_addr_((uintptr_t)original_addr)
        , hook_addr_((uintptr_t)(+hook_addr))
        , is_hooked_(false)
        , restore_block_( *((asm_block_64_ptr)(original_addr)) )
        , hook_block_( (asm_block_64_ptr)(original_addr) )
    {
    }

    ////////////////////////////////////////////////////////////////////////////

    uintptr_t               original_addr_;
    uintptr_t                   hook_addr_;
    bool                        is_hooked_;
    const asm_block_64      restore_block_;
    asm_block_64_ptr           hook_block_;
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


#endif  // VPR_DEVIATE_HEADER
