# Sleepmask-VS

This repository contains a collection of Sleepmask examples to support the development of custom Sleepmask BOFs.
Sleepmask-VS was built using the Beacon Object File Visual Studio template ([BOF-VS](https://github.com/Cobalt-Strike/bof-vs)).
This repository will grow over time to provide additional Sleepmask/BeaconGate examples.

## Quick Start Guide

### Prerequisites:

* An x64 Windows 10/11 development machine (without a security solution)
* Visual Studio Community/Pro/Enterprise 2022 (Desktop Development with C++ installed)
* The Clang compiler for Windows (Visual Studio Installer -> Modify -> Individual Components -> C++ Clang Compiler for Windows)

Note: Sleepmask-VS has been updated to use Clang to facilitate inline assembly blocks (`__asm{}`). Compilation will therefore fail 
if Clang has not been installed. This project has been tested on v17.0.3.

### Cloning the repo:

Sleepmask-VS has been updated to include BOF-VS as a submodule to simplify maintenance and development.
Therefore, `git clone` will not download all of the files required to compile the project. `git submodule init` 
and `git submodule update` are also required to initialize the repository and fetch BOF-VS.

Alternatively, `git clone --recurse-submodules <sleepmask-vs>` will instruct Git to initialize and fetch BOF-VS as part
of cloning Sleepmask-VS.

Note: If you download Sleepmask-VS as a zip, you will need to do the following to correctly configure the submodule dependency:
```
extract zip
git init
rm -r bof-vs
git submodule add https://github.com/cobalt-strike/bof-vs
```

### Debug

The `Debug` target builds Sleepmask-VS as an executable, which 
allows you to benefit from the convenience of debugging it within
Visual Studio. This will enable you to work at the source
code level without running the Sleepmask BOF through a Beacon.

BOF-VS provides a mocking framework to simplify Sleepmask/BeaconGate development. 
As part of calling the `runMockedSleepMask()`/`runMockedBeaconGate()` functions it 
is possible to replicate malleable C2 settings. This can be seen in the example below:

```
int main(int argc, char* argv[]) {
    bof::runMockedSleepMask(sleep_mask,
        {
            .allocator = bof::profile::Allocator::VirtualAlloc,
            .obfuscate = bof::profile::Obfuscate::False,
            .useRWX = bof::profile::UseRWX::False,
            .module = "",
        },
        {
            .sleepTimeMs = 5000,
            .runForever = true,
        }
    );

    return 0;
}
```

To simplify the development of custom gates, it is possible to mock
Beacon's WINAPI calls. `createFunctionCallStructure()` is a helper function that makes it easy to
create `FUNCTION_CALL` structures. `runMockedBeaconGate()` can be used to call the Sleepmask
entry point and pass it a pointer to the generated `FUNCTION_CALL` to replicate Beacon's behaviour.
The following example demonstrates how to proxy a call to `VirtualAlloc` through BeaconGate: 

```
FUNCTION_CALL functionCall = bof::mock::createFunctionCallStructure(
    VirtualAlloc, // Function Pointer
    WinApi::VIRTUALALLOC, // Human readable WinApi enum
    TRUE, // Mask Beacon
    4, // Number of Arguments (for VirtualAlloc)
    GateArg(NULL),  // VirtualAlloc Arg1
    GateArg(0x1000), // VirtualAlloc Arg2 
    GateArg(MEM_RESERVE | MEM_COMMIT), // VirtualAlloc Arg3
    GateArg(PAGE_EXECUTE_READWRITE) // VirtualAlloc Arg4
);

// Run BeaconGate
bof::runMockedBeaconGate(sleep_mask, &functionCall,
    {
        .allocator = bof::profile::Allocator::VirtualAlloc,
        .obfuscate = bof::profile::Obfuscate::False,
        .useRWX = bof::profile::UseRWX::False,
        .module = "",
    });

// Free the memory allocated by BeaconGate
VirtualFree((LPVOID)functionCall.retValue, 0, MEM_RELEASE);
```

Note: In this example we also free the memory created by BeaconGate.

### Release

The `Release` target compiles an object file for use
with Cobalt Strike. 

To use Sleepmask-VS:
1. Enable the Sleepmask (`stage.sleep_mask "true";`)
2. Enable required BeaconGate functions (`stage.beacon_gate { ... }`)
3. Compile Sleepmask-VS
4. Load `sleepmask.cna` in the Script Manager
5. Export a Beacon

### BeaconGate

Sleepmask-VS is intended primarily to function as a library, however to aid novel call stack spoofing development, we have added three BeaconGate PoC examples to demonstrate different call gates:
* indirectsyscalls-sleepmask - This is an example of how to implement indirect syscalls via BeaconGate.
* retaddrspoofing-sleepmask - This is an example of implementing return address spoofing to every WinAPI proxied by Beacon to the sleepmask.
* draugr-sleepmask - This is a port of https://github.com/NtDallas/Draugr to BeaconGate. It combines a gadget with a spoofed stack frame to create a 'legitimate' stack (no unbacked memory).

Additionally, for testing custom call gates we have added:
* A `TestSysCallApi()` function which will unit test the `Core` API set exposed by BeaconGate. This will ensure your call gate works correctly for every WinAPI proxied by Beacon. See the following link for the full list of supported APIs: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-gate.htm.
* A `unit-test-bof` BOF which will call every exported system call API exposed by the BOF C API (i.e. BeaconVirtualAlloc). This can be run via a live Beacon to test call gates work in 'production'. Note, the System Call API exposed to BOFs is a smaller subset of the 'Core' API.

### Logging

You can enable logging for the release build of your Sleepmask via setting the following define in `debug.h`:
```
// Controls logging for the release build
#define ENABLE_LOGGING 1
```
This will output debug information to `OutputDebugString()` and so will be visible via SysInternal's `DbgView` or via attaching a debugger (i.e. `Windbg`). The following shows debug output in `WinDbg` for the `draugr-sleepmask`:
```
SLEEPMASK: Masking Section - Address: 0000000000C9D000
SLEEPMASK: Masking Section - Address: 0000000000CA0000
SLEEPMASK: Calling INTERNETCONNECTA via DraugrGate
Calling INTERNETCONNECTA
Arg 0: 0x0000000000CC0004
Arg 1: 0x00000000000F1520
Arg 2: 0x0000000000000050
Arg 3: 0x0000000000000000
Arg 4: 0x0000000000000000
Arg 5: 0x0000000000000003
Arg 6: 0x0000000000000000
Arg 7: 0x00000000000FE9F0
ModLoad: 00007ffa`8c0c0000 00007ffa`8c0cb000   C:\Windows\SYSTEM32\WINNSI.DLL
DRAUGR: Finding suitable draugr trampoline gadget...
DRAUGR: Trampoline: 0x00007FFA8F8E6A23
DRAUGR: Trampoline func stack size: 192
DRAUGR: Invoking DraugrSpoofStub...
ModLoad: 00007ffa`91050000 00007ffa`91058000   C:\Windows\System32\NSI.dll
DRAUGR: Return value: 0x0000000000CC0008
SLEEPMASK: Unmasking Section - Address: 0000000000C40000
```
