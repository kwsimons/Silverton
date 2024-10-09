# Silverton: An Xbox Code Injector

## Overview

Silverton allows unsigned code execution on a retail Xbox that has been compromised via [Collateral Damage](https://github.com/exploits-forsale/collateral-damage) & [Solstice](https://github.com/exploits-forsale/solstice).

This is performed through the use of the [.NET `msbuild`](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-msbuild) command, a custom PE/Dll injector, native API (`kernelbase`, `advapi32`) interception for LoadLibrary and CreateProcess, and various runtime patches.  Through the use of this tool one can invoke a shell (`cmd.exe`) that is capable of transparently launching and executing unsigned executables (including unsigned Dlls), allowing for rapid development compared to currently used methods.

## Why?

This tool is required due to code integrity checks built into the Windows OS running on the Xbox.  Attempting to execute unsigned executables on the Xbox will result in the `NtCreateUserProcess` syscall (`0xD0`) (invoked via `ntdll!NtCreateUserProcess`) to return `0xC000003A`(`STATUS_OBJECT_PATH_NOT_FOUND`).  Attempting to load unsigned Dlls within a signed executable will result in a `ERROR_PATH_NOT_FOUND`, `ERROR_ACCESS_DENIED` or `ERROR_MOD_NOT_FOUND` error.

## Supported Use Cases & Limitations

This library has not been tested extensively.  It does *not* handle every use case in the world, but it should work for research purposes.  Additionally, the choice to leverage a .NET in-process PE/Dll injection has plenty of limits (besides just being slow).

Devices tested:
* Xbox One X
* Xbox Series S
* Xbox Series X

Versions supported:
* `10.0.22621.2864`
* `10.0.25398.4908`
* `10.0.25398.4909`
* `10.0.25398.4478`

Scenarios tested:
* Unsigned Visual C++ executable with unsigned Dll imports built using MSBuild
* Unsigned .NET 8.0 executables with unsigned Dll imports loaded using a .NET 8.0 loader runtime
* Powershell version 7.3.12 loaded using a .NET 8.0 loader runtime
* Powershell version 7.4+ loaded using a .NET 8.0 loader runtime with environment variable `CLR_ASSEMBLY_INJECTION` set to `SKIP`
* `cmd.exe`, `conhost.exe`, `sshd.exe` & `sftp-server.exe` have all been tested and confirmed to work

Known limitations:
* 32-bit executables or 32-bit Dlls cannot be injected (but can be loaded natively)
* Attempting to run .NET executables using this tool may encounter strange issues.  In some scenarios, setting the environment variable `CLR_ASSEMBLY_INJECTION` to `FORCE` or `SKIP` may allow for the .NET executable to succeed
	* This is due to the fact that there are essentially two CLRs, as well as P/Invoke callbacks crossing CLR boundaries.  `CLRInjector.exe` contains logic to attempt to load CLRs natively when possible, but there can be application-specific issues.

## Installation

1. On your PC, create a directory called `xbox`
1. Download the [.NET 8.0 SDK binaries](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/sdk-8.0.402-windows-x64-binaries) and extract them to `xbox\dotnet`
1. Copy the files in this repositories `payloads` directory to `xbox\payloads`
1. Package this repository and copy the output to (`Silverton.dll`, etc) to `xbox\payloads\launcher`
1. *Optionally*, you may [download `Powershell-7.3.12-win-x64.zip`](https://github.com/PowerShell/PowerShell/releases/tag/v7.3.12) and unzip its contents to `xbox\pwsh`
	* NOTE: Powershell 7.4+ will only work with `CLR_ASSEMBLY_INJECTION=SKIP`
1. Copy the `xbox` directory to the root of your USB drive
1. Connect the USB drive to your Xbox

At this point, your Xbox will have access to the `D:\xbox` directory on your USB drive.

NOTE: If you'd like to install it to a different location (eg `S:\`), see the "Configuration" section for necessary changes.

## Usage

You will first need to leverage Collateral Damage & Solstice to gain shell access on the Xbox, then you can issue the commands outlined below.

Spawn a new command prompt (`cmd.exe`) that allows for unsigned binary execution:
```
D:\xbox\payloads\cmd.bat
```

Alternatively, if you opted to download & copy Powershell as per the installation instructions, you can spawn a new Powershell that allows for unsigned binary execution:
```
D:\xbox\payloads\powershell.bat
```

Executables launched from within these shells will be intercepted and launched via the custom process launcher or loaded natively based on the configuration in `initialize.xml` (see "Configuration")

If you want to invoke an executable directly, without one of the shells listed above, use the following command:
```
D:\xbox\dotnet\dotnet.exe msbuild "D:\xbox\payloads\initialize.xml" -property:LauncherDirectory="D:\xbox\payloads\launcher" -property:WorkingDirectory="C:\\" -property:Command="C:\windows\system32\cmd.exe /C echo Hello world from the injected cmd.exe" -property:LogLevel="5"
```

## Configuration

### `config.bat`

This file is used by `init.bat` to initialize environment variables used by the different payloads in the same directory.

Configurations:
* `DOTNET_DIRECTORY`: The absolute path to the .NET SDK directory containing `dotnet.exe`
* `MSBUILD_XML_PATH`: The absolute path to the MSBuild project XML file location (`initialize.xml`)
* `LAUNCHER_DIRECTORY`: The absolute path to the directory containing the launcher (`Silverton.dll`)
* `LOG_LEVEL`: The log level used by the launcher

### `initialize.xml`

This is the MSBuild project file, it is used by the `dotnet.exe msbuild` command to invoke the Launcher.

Configurations:
* `NativeExecutionDirectories`: A semi-colon delimited list of absolute directory paths whose files will be loaded *natively* (not loaded by this tool)
* `NativeExecutionBlockList`: A semi-colon delimited list of absolute file paths of files that will *always* be loaded by our tool, regardless of their presence in the `NativeExecutionDirectories` directories.

NOTE: All other properties in this file can be ignored when not invoking the MSBuild command directly.

### Environment Variables

* `CLR_ASSEMBLY_INJECTION`
	* `FORCE` = Force the EXE to be loaded into the current CLR and executed as a native assembly
	* `SKIP` = Force the EXE to be loaded outside of the current CLR via normal PE injection and invocation

## Debugging

If you encounter issues using this tool, your best bet is to modify the logging level (see "Configuration") to `5` (TRACE).  This will produce verbose logging of the internals of the tool that can aide in debugging.  Please include these logs in any issues created.

## FAQ

### Why the reliance on .NET MSBuild?

The `dotnet.exe` is a signed executable and thus allowed to be invoked natively on the Xbox.  By utilizing it's `msbuild` command we gain the ability to load and execute arbitrary .NET Dlls.  This is the entry point that allows us to bypass code signing checks. 

### Why the reliance on .NET for each spawned process after the initial MSBuild invocation?

No real technical limitation here.  Opted to work in a less forgiving world while learning about windows internals and I am too lazy to port it to modify a suspended remote process.  This can be addressed in the future, leveraging the MSBuild entry point only on the first process invocation.  Compatibility and speed gains are possible here.

### Why do my programs take longer to start when I use this tool?

The actual code being executed is fairly performant, but the underlying .NET and MSBuild code comes with an overhead.  This cost can be mitigated if the code is ported to not rely on .NET MSBuild invocation for each new spawned process.

### Why doesn't it work for my random executable?

The loader internals and logic are generally well understood, but it's likely this tools implementation is half-hearted, and the reliance on the .NET runtime can cause unintended problems.

### Does this tool support executables with unsigned Dll dependencies?

Yes, the tool intercepts library loading and will first attempt to load the Dll natively.  If that fails due to OS security failures, the Dll be then be injected into the program via the custom PE/Dll loader.

### Does this tool allow for a program to spawn a new process that is an unsigned executable?

Yes, the tool intercepts process creation and will route all new processes through the custom process launcher, allowing for unsigned executables to be spawned.

## How to build

Using .NET SDK 8.0+, invoke the following command:
```
dotnet publish /p:PublishProfile=FolderProfile
```

## How it works

Let's wait and see if it works first ...

<!---
PE/Dll loader support:
* TLS callback invocation
* `DllMain` invocation
* Static TLS initialization
* PEB & LDRP updates
* `LoadLibrary*()` interception
* Various patches to allow for native method use
* See `InMemory.cs` & `InjectedPE.cs` for more
-->

## Resources

* https://github.com/exploits-forsale/collateral-damage
* https://github.com/exploits-forsale/solstice
* https://landaire.net/reflective-pe-loader-for-xbox/
* https://xboxoneresearch.github.io
* https://github.com/nettitude/RunPE
* https://github.com/DarthTon/Blackbone
* https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks
* https://elliotonsecurity.com/what-is-loader-lock
* https://github.com/dotnet/msbuild
* https://github.com/dotnet/runtime

## TODO

* Add support for `10.0.25398.4908`
* Port the PE/Dll injection part of this library to not rely on a CLR to run (eg C++)
* Invoke the executable in a new thread
* Properly detect when a native exe can be invoked without injection
* Cleanup process pipes
* CLR `LibraryImportAttribute` is not being hijacked