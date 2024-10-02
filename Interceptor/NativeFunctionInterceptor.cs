using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using static Silverton.Core.Interop.NativeBridge;
using System.ComponentModel;
using Silverton.Core.Log;
using Silverton.Core.Image;
using System.Diagnostics;
using Silverton.Injector;

/*
 * TODO:
 * [ ] Hook CreateProcessInternal*()
 * [ ] Verify that the memory we use to write the trampoline opcodes in the PEB is unused
 */
namespace Silverton.Interceptor {

    // Responsible for intercepting LoadLibrary* and CreateProcess* methods, swapping them out for our custom implementations.
    public class NativeFunctionInterceptor {

        private static bool interceptsInstalled = false;

        // We must keep references to the override functions otherwise they will be garbage collected
        private static LoadLibraryW kernelbase_LoadLibraryW = null;
        private static LoadLibraryA kernelbase_LoadLibraryA = null;
        private static LoadLibraryExW kernelbase_LoadLibraryExW = null;
        private static LoadLibraryExA kernelbase_LoadLibraryExA = null;
        private static CreateProcessW kernelbase_CreateProcessW = null;
        private static CreateProcessA kernelbase_CreateProcessA = null;
        private static CreateProcessAsUserW kernelbase_CreateProcessAsUserW = null;
        private static CreateProcessAsUserA kernelbase_CreateProcessAsUserA = null;
        private static CreateProcessWithLogonW kernelbase_CreateProcessWithLogonW = null;
        // TODO: kernel32.dll!CreateProcessInternalA ?
        // TODO: kernel32.dll!CreateProcessInternalW ?

        public static IntPtr GetNativeLoadLibraryAddress() {
            // Get the original LoadLibrary function address to allow for native loading later
            IntPtr module = GetModuleHandle("kernelbase.dll");
            return GetProcAddress(module, "LoadLibraryExW");
        }

        public static void InstallIntercepts(DllLoader dllResolver, NewProcessInterceptor newProcessInterceptor) {
            if (interceptsInstalled) {
                return;
            }

            kernelbase_LoadLibraryW = HookLoadLibrary("kernelbase.dll", "LoadLibraryW", dllResolver, LoadLibraryW_Intercept);
            kernelbase_LoadLibraryA = HookLoadLibrary("kernelbase.dll", "LoadLibraryA", dllResolver, LoadLibraryA_Intercept);
            kernelbase_LoadLibraryExW = HookLoadLibrary("kernelbase.dll", "LoadLibraryExW", dllResolver, LoadLibraryExW_Intercept);
            kernelbase_LoadLibraryExA = HookLoadLibrary("kernelbase.dll", "LoadLibraryExA", dllResolver, LoadLibraryExA_Intercept);
            kernelbase_CreateProcessW = HookCreateProcess("kernelbase.dll", "CreateProcessW", newProcessInterceptor, CreateProcessW_Intercept);
            kernelbase_CreateProcessA = HookCreateProcess("kernelbase.dll", "CreateProcessA", newProcessInterceptor, CreateProcessA_Intercept);
            kernelbase_CreateProcessAsUserW = HookCreateProcess("advapi32.dll", "CreateProcessAsUserW", newProcessInterceptor, CreateProcessAsUserW_Intercept);
            kernelbase_CreateProcessAsUserA = HookCreateProcess("advapi32.dll", "CreateProcessAsUserA", newProcessInterceptor, CreateProcessAsUserA_Intercept);
            kernelbase_CreateProcessWithLogonW = HookCreateProcess("advapi32.dll", "CreateProcessWithLogonW", newProcessInterceptor, CreateProcessWithLogonW_Intercept);

            interceptsInstalled = true;
            Logger.Log($"Intercepts installed", Logger.LogLevel.DEBUG);
        }

        private static LoadLibraryW LoadLibraryW_Intercept(DllLoader dllResolver, IntPtr nativeFunctionAddress) {
            return (lpLibFileName) => {
                try {
                    Logger.Log($"######### HIJACK LoadLibraryW({lpLibFileName}) ##########", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpLibFileName: {lpLibFileName}", Logger.LogLevel.TRACE);

                    IntPtr result = IntPtr.Zero;
                    int errorCode = 0;
                    try {
                        var dllHandle = dllResolver.LoadLibrary(lpLibFileName, 0);
                        errorCode = Marshal.GetLastWin32Error();
                        result = dllHandle;
                    } catch (Win32Exception e) {
                        errorCode = e.NativeErrorCode;
                    }

                    Logger.Log($"LoadLibraryW({lpLibFileName}) result: {result} (Error Code: 0x{errorCode:X})", Logger.LogLevel.DEBUG);
                    SetLastError((uint)errorCode);
                    return result;
                } catch (Exception e) {
                    Logger.Log($"Error invoking LoadLibraryW({lpLibFileName}):\n{e.ToString()}\n", Logger.LogLevel.ERROR);
                    SetLastError(0xDEAD);
                    return IntPtr.Zero;
                }
            };
        }

        private static LoadLibraryA LoadLibraryA_Intercept(DllLoader dllResolver, IntPtr nativeFunctionAddress) {
            return (lpLibFileName) => {
                try {
                    Logger.Log($"######### HIJACK LoadLibraryA({lpLibFileName}) ##########", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpLibFileName: {lpLibFileName}", Logger.LogLevel.TRACE);

                    IntPtr result = IntPtr.Zero;
                    int errorCode = 0;
                    try {
                        var dllHandle = dllResolver.LoadLibrary(lpLibFileName, 0);
                        errorCode = Marshal.GetLastWin32Error();
                        result = dllHandle;
                    } catch (Win32Exception e) {
                        errorCode = e.NativeErrorCode;
                    }

                    Logger.Log($"LoadLibraryA({lpLibFileName}) result: {result} (Error Code: 0x{errorCode:X})", Logger.LogLevel.DEBUG);
                    SetLastError((uint)errorCode);
                    return result;
                } catch (Exception e) {
                    Logger.Log($"Error invoking LoadLibraryA({lpLibFileName}):\n{e.ToString()}\n", Logger.LogLevel.ERROR);
                    SetLastError(0xDEAD);
                    return IntPtr.Zero;
                }
            };
        }

        private static LoadLibraryExW LoadLibraryExW_Intercept(DllLoader dllResolver, IntPtr nativeFunctionAddress) {
            return (lpLibFileName, hFile, dwFlags) => {
                try {
                    Logger.Log($"######### HIJACK LoadLibraryExW({lpLibFileName}) ##########", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpLibFileName: {lpLibFileName}", Logger.LogLevel.TRACE);
                    Logger.Log($"hFile: 0x{hFile:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"dwFlags: 0x{dwFlags:X}", Logger.LogLevel.TRACE);

                    IntPtr result = IntPtr.Zero;
                    int errorCode = 0;
                    try {
                        result = dllResolver.LoadLibrary(lpLibFileName, dwFlags);
                        errorCode = Marshal.GetLastWin32Error();
                    } catch (Win32Exception e) {
                        errorCode = e.NativeErrorCode;
                    }

                    Logger.Log($"LoadLibraryExW({lpLibFileName}) result: 0x{result:X} (Error Code: 0x{errorCode:X})", Logger.LogLevel.DEBUG);
                    SetLastError((uint)errorCode);
                    return result;
                } catch (Exception e) {
                    Logger.Log($"Error invoking LoadLibraryExW({lpLibFileName}):\n{e.ToString()}\n", Logger.LogLevel.ERROR);
                    SetLastError(0xDEAD);
                    return IntPtr.Zero;
                }
            };
        }

        private static LoadLibraryExA LoadLibraryExA_Intercept(DllLoader dllResolver, IntPtr nativeFunctionAddress) {
            return (lpLibFileName, hFile, dwFlags) => {
                try {
                    Logger.Log($"######### HIJACK LoadLibraryExA({lpLibFileName}) ##########", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpLibFileName: {lpLibFileName}", Logger.LogLevel.TRACE);
                    Logger.Log($"hFile: 0x{hFile:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"dwFlags: 0x{dwFlags:X}", Logger.LogLevel.TRACE);

                    IntPtr result = IntPtr.Zero;
                    int errorCode = 0;
                    try {
                        var dllHandle = dllResolver.LoadLibrary(lpLibFileName, dwFlags);
                        errorCode = Marshal.GetLastWin32Error();
                        result = dllHandle;
                    } catch (Win32Exception e) {
                        errorCode = e.NativeErrorCode;
                    }

                    Logger.Log($"LoadLibraryExA() result: {result} (Error Code: 0x{errorCode:X})", Logger.LogLevel.DEBUG);
                    SetLastError((uint)errorCode);
                    return result;
                } catch (Exception e) {
                    Logger.Log($"Error invoking LoadLibraryExA({lpLibFileName}):\n{e.ToString()}\n", Logger.LogLevel.ERROR);
                    SetLastError(0xDEAD);
                    return IntPtr.Zero;
                }
            };
        }

        private static CreateProcessW CreateProcessW_Intercept(NewProcessInterceptor newProcessInterceptor, IntPtr nativeFunctionAddress) {
            return (string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation) => {
                try {
                    Logger.Log($"######### HIJACK CreateProcessW ##########", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpApplicationName: '{lpApplicationName}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpCommandLine: '{lpCommandLine}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpCurrentDirectory: '{lpCurrentDirectory}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpEnvironment: 0x{lpEnvironment}", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpProcessAttributes: 0x{lpProcessAttributes:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpThreadAttributes: 0x{lpThreadAttributes:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"bInheritHandles: {bInheritHandles}", Logger.LogLevel.TRACE);
                    Logger.Log($"dwCreationFlags: 0x{dwCreationFlags}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpStartupInfo: 0x{lpStartupInfo:X}", Logger.LogLevel.TRACE);

                    // Hijack the process
                    (lpApplicationName, lpCommandLine) = newProcessInterceptor.PatchApplicationAndCommand(lpCurrentDirectory, lpApplicationName, lpCommandLine, lpStartupInfo);
                    dwCreationFlags = newProcessInterceptor.PatchCreationFlags(dwCreationFlags);
                    lpEnvironment = newProcessInterceptor.PatchEnvironmentVariableBlock(lpEnvironment, false, false);
                    Logger.Log($"(hijacked) lpApplicationName: {lpApplicationName}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) lpCommandLine: {lpCommandLine}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) dwCreationFlags: {dwCreationFlags}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) lpEnvironment: {lpEnvironment}", Logger.LogLevel.DEBUG);

                    var nativeFn = Marshal.GetDelegateForFunctionPointer<CreateProcessW>(nativeFunctionAddress);
                    var result = nativeFn(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, ref lpProcessInformation);
                    uint errorCode = (uint)Marshal.GetLastWin32Error();

                    Logger.Log($"CreateProcessW() result: {result} (Error Code: 0x{errorCode:X})", Logger.LogLevel.DEBUG);
                    Logger.Log($"\thProcess = {lpProcessInformation.hProcess}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tdwProcessId = {lpProcessInformation.dwProcessId}", Logger.LogLevel.TRACE);
                    SetLastError(errorCode);

                    return result;
                } catch (Exception e) {
                    Logger.Log($"Error invoking CreateProcessW({lpCommandLine}):\n{e.ToString()}\n", Logger.LogLevel.ERROR);
                    SetLastError(0xDEAD);
                    return false;
                }
            };
        }

        private static CreateProcessA CreateProcessA_Intercept(NewProcessInterceptor newProcessInterceptor, IntPtr nativeFunctionAddress) {
            return (string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation) => {
                try {
                    Logger.Log($"######### HIJACK CreateProcessA ##########", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpApplicationName: '{lpApplicationName}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpCommandLine: '{lpCommandLine}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpCurrentDirectory: '{lpCurrentDirectory}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpEnvironment: 0x{lpEnvironment}", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpProcessAttributes: 0x{lpProcessAttributes:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpThreadAttributes: 0x{lpThreadAttributes:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"bInheritHandles: {bInheritHandles}", Logger.LogLevel.TRACE);
                    Logger.Log($"dwCreationFlags: 0x{dwCreationFlags}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpStartupInfo: 0x{lpStartupInfo:X}", Logger.LogLevel.TRACE);

                    // Hijack the process
                    (lpApplicationName, lpCommandLine) = newProcessInterceptor.PatchApplicationAndCommand(lpCurrentDirectory, lpApplicationName, lpCommandLine, lpStartupInfo);
                    dwCreationFlags = newProcessInterceptor.PatchCreationFlags(dwCreationFlags);
                    lpEnvironment = newProcessInterceptor.PatchEnvironmentVariableBlock(lpEnvironment, false, false);
                    Logger.Log($"(hijacked) lpApplicationName: {lpApplicationName}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) lpCommandLine: {lpCommandLine}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) dwCreationFlags: {dwCreationFlags}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) lpEnvironment: {lpEnvironment}", Logger.LogLevel.DEBUG);

                    var nativeFn = Marshal.GetDelegateForFunctionPointer<CreateProcessA>(nativeFunctionAddress);
                    var result = nativeFn(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, ref lpProcessInformation);
                    uint errorCode = (uint)Marshal.GetLastWin32Error();

                    Logger.Log($"CreateProcessA() result: {result} (Error Code: 0x{errorCode:X})", Logger.LogLevel.DEBUG);
                    Logger.Log($"\thProcess = {lpProcessInformation.hProcess}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tdwProcessId = {lpProcessInformation.dwProcessId}", Logger.LogLevel.TRACE);
                    SetLastError(errorCode);

                    return result;
                } catch (Exception e) {
                    Logger.Log($"Error invoking CreateProcessA({lpCommandLine}):\n{e.ToString()}\n", Logger.LogLevel.ERROR);
                    SetLastError(0xDEAD);
                    return false;
                }
            };
        }

        private static CreateProcessAsUserW CreateProcessAsUserW_Intercept(NewProcessInterceptor newProcessInterceptor, IntPtr nativeFunctionAddress) {
            return (IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation) => {
                try {
                    Logger.Log($"######### HIJACK CreateProcessAsUserW ##########", Logger.LogLevel.DEBUG);
                    Logger.Log($"hToken: 0x{hToken:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpApplicationName: '{lpApplicationName}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpCommandLine: '{lpCommandLine}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpCurrentDirectory: '{lpCurrentDirectory}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpEnvironment: 0x{lpEnvironment}", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpProcessAttributes: 0x{lpProcessAttributes:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpThreadAttributes: 0x{lpThreadAttributes:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"bInheritHandles: {bInheritHandles}", Logger.LogLevel.TRACE);
                    Logger.Log($"dwCreationFlags: 0x{dwCreationFlags}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpStartupInfo: 0x{lpStartupInfo:X}", Logger.LogLevel.TRACE);

                    // Hijack the process
                    (lpApplicationName, lpCommandLine) = newProcessInterceptor.PatchApplicationAndCommand(lpCurrentDirectory, lpApplicationName, lpCommandLine, lpStartupInfo);
                    dwCreationFlags = newProcessInterceptor.PatchCreationFlags(dwCreationFlags);
                    lpEnvironment = newProcessInterceptor.PatchEnvironmentVariableBlock(lpEnvironment, true, false);
                    Logger.Log($"(hijacked) lpApplicationName: {lpApplicationName}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) lpCommandLine: {lpCommandLine}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) dwCreationFlags: {dwCreationFlags}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) lpEnvironment: {lpEnvironment}", Logger.LogLevel.DEBUG);

                    var nativeFn = Marshal.GetDelegateForFunctionPointer<CreateProcessAsUserW>(nativeFunctionAddress);
                    var result = nativeFn(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, ref lpProcessInformation);
                    uint errorCode = (uint)Marshal.GetLastWin32Error();

                    Logger.Log($"CreateProcessAsUserW() result: {result} (Error Code: 0x{errorCode:X})", Logger.LogLevel.DEBUG);
                    Logger.Log($"\thProcess = {lpProcessInformation.hProcess}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tdwProcessId = {lpProcessInformation.dwProcessId}", Logger.LogLevel.TRACE);
                    SetLastError(errorCode);

                    return result;
                } catch (Exception e) {
                    Logger.Log($"Error invoking CreateProcessAsUserW({lpCommandLine}):\n{e.ToString()}\n", Logger.LogLevel.ERROR);
                    SetLastError(0xDEAD);
                    return false;
                }
            };
        }

        private static CreateProcessAsUserA CreateProcessAsUserA_Intercept(NewProcessInterceptor newProcessInterceptor, IntPtr nativeFunctionAddress) {
            return (IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation) => {
                try {
                    Logger.Log($"######### HIJACK CreateProcessAsUserA ##########", Logger.LogLevel.DEBUG);
                    Logger.Log($"hToken: 0x{hToken:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpApplicationName: '{lpApplicationName}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpCommandLine: '{lpCommandLine}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpCurrentDirectory: '{lpCurrentDirectory}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpEnvironment: 0x{lpEnvironment}", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpProcessAttributes: 0x{lpProcessAttributes:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpThreadAttributes: 0x{lpThreadAttributes:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"bInheritHandles: {bInheritHandles}", Logger.LogLevel.TRACE);
                    Logger.Log($"dwCreationFlags: 0x{dwCreationFlags}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpStartupInfo: 0x{lpStartupInfo:X}", Logger.LogLevel.TRACE);

                    // Hijack the process
                    (lpApplicationName, lpCommandLine) = newProcessInterceptor.PatchApplicationAndCommand(lpCurrentDirectory, lpApplicationName, lpCommandLine, lpStartupInfo);
                    dwCreationFlags = newProcessInterceptor.PatchCreationFlags(dwCreationFlags);
                    lpEnvironment = newProcessInterceptor.PatchEnvironmentVariableBlock(lpEnvironment, true, false);
                    Logger.Log($"(hijacked) lpApplicationName: {lpApplicationName}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) lpCommandLine: {lpCommandLine}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) dwCreationFlags: {dwCreationFlags}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) lpEnvironment: {lpEnvironment}", Logger.LogLevel.DEBUG);

                    var nativeFn = Marshal.GetDelegateForFunctionPointer<CreateProcessAsUserA>(nativeFunctionAddress);
                    var result = nativeFn(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, ref lpProcessInformation);
                    uint errorCode = (uint)Marshal.GetLastWin32Error();

                    Logger.Log($"CreateProcessAsUserA() result: {result} (Error Code: 0x{errorCode:X})", Logger.LogLevel.DEBUG);
                    Logger.Log($"\thProcess = {lpProcessInformation.hProcess}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tdwProcessId = {lpProcessInformation.dwProcessId}", Logger.LogLevel.TRACE);
                    SetLastError(errorCode);

                    return result;
                } catch (Exception e) {
                    Logger.Log($"Error invoking CreateProcessAsUserA({lpCommandLine}):\n{e.ToString()}\n", Logger.LogLevel.ERROR);
                    SetLastError(0xDEAD);
                    return false;
                }
            };
        }

        private static CreateProcessWithLogonW CreateProcessWithLogonW_Intercept(NewProcessInterceptor newProcessInterceptor, IntPtr nativeFunctionAddress) {
            return (string lpUsername, string lpDomain, string lpPassword, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation) => {
                try {
                    Logger.Log($"######### HIJACK CreateProcessWithLogonW ##########", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpUsername: {lpUsername}", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpDomain: {lpDomain}", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpPassword: <redacted>", Logger.LogLevel.TRACE);
                    Logger.Log($"dwLogonFlags: 0x{dwLogonFlags:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpApplicationName: '{lpApplicationName}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpCommandLine: '{lpCommandLine}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpCurrentDirectory: '{lpCurrentDirectory}'", Logger.LogLevel.DEBUG);
                    Logger.Log($"lpEnvironment: 0x{lpEnvironment}", Logger.LogLevel.DEBUG);
                    Logger.Log($"dwCreationFlags: 0x{dwCreationFlags}", Logger.LogLevel.TRACE);
                    Logger.Log($"lpStartupInfo: 0x{lpStartupInfo:X}", Logger.LogLevel.TRACE);

                    // Hijack the process
                    (lpApplicationName, lpCommandLine) = newProcessInterceptor.PatchApplicationAndCommand(lpCurrentDirectory, lpApplicationName, lpCommandLine, lpStartupInfo);
                    dwCreationFlags = newProcessInterceptor.PatchCreationFlags(dwCreationFlags);
                    lpEnvironment = newProcessInterceptor.PatchEnvironmentVariableBlock(lpEnvironment, true, true);
                    Logger.Log($"(hijacked) lpApplicationName: {lpApplicationName}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) lpCommandLine: {lpCommandLine}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) dwCreationFlags: {dwCreationFlags}", Logger.LogLevel.DEBUG);
                    Logger.Log($"(hijacked) lpEnvironment: {lpEnvironment}", Logger.LogLevel.DEBUG);

                    var nativeFn = Marshal.GetDelegateForFunctionPointer<CreateProcessWithLogonW>(nativeFunctionAddress);
                    var result = nativeFn(lpUsername, lpDomain, lpPassword, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, ref lpProcessInformation);
                    uint errorCode = (uint)Marshal.GetLastWin32Error();

                    Logger.Log($"CreateProcessWithLogonW() result: {result} (Error Code: 0x{errorCode:X})", Logger.LogLevel.DEBUG);
                    Logger.Log($"\thProcess = {lpProcessInformation.hProcess}", Logger.LogLevel.TRACE);
                    Logger.Log($"\tdwProcessId = {lpProcessInformation.dwProcessId}", Logger.LogLevel.TRACE);
                    SetLastError(errorCode);

                    return result;
                } catch (Exception e) {
                    Logger.Log($"Error invoking CreateProcessWithLogonW({lpCommandLine}):\n{e.ToString()}\n", Logger.LogLevel.ERROR);
                    SetLastError(0xDEAD);
                    return false;
                }
            };
        }

        private delegate T HijackedLoadLibrary<T>(DllLoader dllResolver, IntPtr functionAddress);

        private static T HookLoadLibrary<T>(string dllName, string functionName, DllLoader dllResolver, HijackedLoadLibrary<T> interceptFunctionFactory) {

            // Get the original function address
            IntPtr module = GetModuleHandle(dllName);
            IntPtr nativeFunctionAddress = GetProcAddress(module, functionName);

            // Create our hijacked callback, with a reference to the original
            T interceptFunction = interceptFunctionFactory(dllResolver, nativeFunctionAddress);
            IntPtr hijackedFunctionAddress = Marshal.GetFunctionPointerForDelegate(interceptFunction);

            Logger.Log($"Diverted function address {dllName}!{functionName} from 0x{nativeFunctionAddress:X} to 0x{hijackedFunctionAddress:X}", Logger.LogLevel.DEBUG);

            // Patch all loaded DLLs Import Address Tables(IAT) references to LoadLibrary / CreateProcess
            PatchImportCalls(dllName, functionName, hijackedFunctionAddress);

            return interceptFunction;
        }

        private delegate T HijackedCreateProcessFactory<T>(NewProcessInterceptor newProcessInterceptor, IntPtr functionAddress);

        private static T HookCreateProcess<T>(string dllName, string functionName, NewProcessInterceptor newProcessInterceptor, HijackedCreateProcessFactory<T> interceptFunctionFactory) {

            // Get the original function address
            IntPtr module = GetModuleHandle(dllName);
            IntPtr nativeFunctionAddress = GetProcAddress(module, functionName);

            // Create our hijacked callback, with a reference to the original
            T interceptFunction = interceptFunctionFactory(newProcessInterceptor, nativeFunctionAddress);
            IntPtr hijackedFunctionAddress = Marshal.GetFunctionPointerForDelegate(interceptFunction);

            Logger.Log($"Diverted function address {dllName}!{functionName} from 0x{nativeFunctionAddress:X} to 0x{hijackedFunctionAddress:X}", Logger.LogLevel.DEBUG);

            // Patch all loaded DLLs Import Address Tables(IAT) references to LoadLibrary / CreateProcess
            PatchImportCalls(dllName, functionName, hijackedFunctionAddress);

            return interceptFunction;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        public delegate IntPtr LoadLibraryW(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Ansi)]
        public delegate IntPtr LoadLibraryA(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        public delegate IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, int dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Ansi)]
        public delegate IntPtr LoadLibraryExA(string lpFileName, IntPtr hFile, int dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        public delegate bool CreateProcessW(
            [MarshalAs(UnmanagedType.LPTStr)]
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPTStr)]
            string lpCurrentDirectory,
            IntPtr lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation
        );

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Ansi)]
        public delegate bool CreateProcessA(
            [MarshalAs(UnmanagedType.LPTStr)]
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPTStr)]
            string lpCurrentDirectory,
            IntPtr lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation
        );

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        public delegate bool CreateProcessAsUserW(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            IntPtr lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Ansi)]
        public delegate bool CreateProcessAsUserA(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            IntPtr lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        public delegate bool CreateProcessWithLogonW(
            string lpUserName,
            string lpDomain,
            string lpPassword,
            uint dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            IntPtr lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation
        );

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        public delegate bool CreateProcessWithTokenW(
            IntPtr hToken,
            uint dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            IntPtr lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation);


        // ##############################################################################################################################
        // ##############################################################################################################################
        // ##############################################################################################################################

        // Where, in the in-memory PE, to begin writing the trampolines
        private static Dictionary<string, int> TRAMPOLINE_FUNCTION_OFFSETS = new Dictionary<string, int>() { {"kernelbase.dll", 0x400}, {"advapi32.dll", 0x400}, };

        /*
         * Modifies the loaded in-memory PEs in order to intercept and redirect the given function calls.
         * 
         * Step 1) Iterates over all modules in the process, updating their import tables function addresses to point to our interceptor functions.
         * Step 2) For the Dll we are intercepting, place trampolines to our function *within* the PEB header, then updating export tables function addresses to point to our trampoline addresses.
         */
        private static IntPtr PatchImportCalls(string dllName, string functionName, IntPtr interceptorFunctionAddress) {

            // Find the original method addresses
            IntPtr pNativeModule = GetModuleHandle(dllName);
            if (pNativeModule == IntPtr.Zero) {
                throw new Exception($"Cannot load module handle for '{dllName}");
            }
            IntPtr pNativeAddress = GetProcAddress(pNativeModule, functionName);
            if (pNativeAddress == IntPtr.Zero) {
                throw new Exception($"Cannot find address for {dllName}!{functionName}");
            }

            Logger.Log($"Hijacking {dllName}!{functionName} (NativeAddress: 0x{pNativeAddress:X} HijackedAddress: 0x{interceptorFunctionAddress:X})", Logger.LogLevel.TRACE);

            // Iterate over all modules loaded into the process
            IntPtr pebAddress = GetPEBAddress(Process.GetCurrentProcess().Handle);

            PEB peb = (PEB)Marshal.PtrToStructure(pebAddress, typeof(PEB));
            PEB_LDR_DATA ldr = (PEB_LDR_DATA)Marshal.PtrToStructure(peb.Ldr, typeof(PEB_LDR_DATA));

            var flink = ldr.InLoadOrderLinks.Flink;
            var entry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(LDR_DATA_TABLE_ENTRY));
            while (entry.InLoadOrderLinks.Flink != ldr.InLoadOrderLinks.Flink) {

                if (entry.BaseDllName.ToString().ToUpper() != Assembly.GetExecutingAssembly().Location.ToUpper()) {

                    string dllNameLower = entry.BaseDllName.ToString().ToLower();

                    IntPtr baseAddress = GetModuleHandle(entry.BaseDllName.ToString());
                    PEImage pe = PEImage.PEReader.ParseLoadedModule(baseAddress);
                    //Logger.Log($"BaseAddress: 0x{baseAddress:X}");

                    if (pe.Is32Bit) {
                        throw new Exception("Unable to support 32-bit");
                    }

                    // Patch all loaded DLLs Import Address Tables(IAT) references
                    var importTable = pe.OptionalHeader64.ImportTable;
                    if (importTable.Size > 0) {

                        //Logger.Log($"ImportTable VirtualAddress: 0x{importTable.VirtualAddress:X} - 0x{importTable.VirtualAddress + importTable.Size:X}");

                        var SIZE_OF_IMAGE_IMPORT_DESCRIPTOR_STRUCT = (uint)Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));

                        // Iterate over the IMAGE_IMPORT_DESCRIPTORS
                        // NOTE: The last IMAGE_IMPORT_DESCRIPTOR of the array is zeroed-out (NULL-Padded) to indicate the end of the Import Directory Table.
                        for (uint importDescriptorOffset = importTable.VirtualAddress; importDescriptorOffset < importTable.VirtualAddress + importTable.Size - SIZE_OF_IMAGE_IMPORT_DESCRIPTOR_STRUCT; importDescriptorOffset += SIZE_OF_IMAGE_IMPORT_DESCRIPTOR_STRUCT) {

                            // Retrieve the IMAGE_IMPORT_DESCRIPTOR
                            IMAGE_IMPORT_DESCRIPTOR importDescriptor = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(IntPtr.Add(baseAddress, (int)importDescriptorOffset), typeof(IMAGE_IMPORT_DESCRIPTOR));

                            if (importDescriptor.Name == 0) {
                                //Logger.Log($"IMAGE_IMPORT_DESCRIPTOR is corrupt for {entry.BaseDllName.ToString()}", Logger.LogLevel.WARN);
                                break;
                            }

                            string importDllName = Marshal.PtrToStringAnsi(IntPtr.Add(baseAddress, (int)importDescriptor.Name));

                            //Logger.Log($"IMAGE_IMPORT_DESCRIPTORS at 0x{importDescriptorOffset:X} (ForwarderChain: 0x{importDescriptor.ForwarderChain:X} OriginalFirstThunk: 0x{importDescriptor.OriginalFirstThunk:X}  TimeDateStamp: 0x{importDescriptor.TimeDateStamp:X} NameAddress: 0x{importDescriptor.Name:X} Name: '{importDllName}' FirstThunk: 0x{importDescriptor.FirstThunk:X})");

                            // Iterate through the IMAGE_LOOKUP_ENTRY in the Image Address Table (IAT, Thunk)
                            for (uint imageLookupEntryAddress = importDescriptor.FirstThunk; true; imageLookupEntryAddress += 8) {
                                //Logger.Log($"imageLookupEntryAddress: 0x{imageLookupEntryAddress:X}");

                                IntPtr pFunctionAddress = IntPtr.Add(baseAddress, (int)imageLookupEntryAddress);
                                long imageImportByNameAddress = Marshal.ReadInt64(pFunctionAddress);

                                // The array of IMAGE_LOOKUP_ENTRYs is terminated with an all-zero entry
                                if (imageImportByNameAddress == 0) {
                                    break;
                                }

                                if (imageImportByNameAddress == pNativeAddress.ToInt64()) {

                                    AllowMemoryWrite(pFunctionAddress, 0, () => {
                                        // Overwrite it
                                        Marshal.WriteInt64(IntPtr.Add(baseAddress, (int)imageLookupEntryAddress), interceptorFunctionAddress.ToInt64());
                                    });

                                    Logger.Log($"Patched import in {entry.FullDllName} 0x{pFunctionAddress:X}", Logger.LogLevel.TRACE);
                                }
                            }
                        }
                    }

                    // Patch the targeted dlls exported function address table
                    // NOTE: This is needed for late-binding or DLLs loaded later that will try to find the address
                    if (entry.BaseDllName.ToString().ToUpper() == dllName.ToUpper()) {

                        // Get the exported functions
                        if (pe.optionalHeader64.ExportTable.Size > 0) {

                            long exportTableAddress = baseAddress.ToInt64() + pe.optionalHeader64.ExportTable.VirtualAddress;
                            //Logger.Log($"ExportTable.AbsoluteAddress: 0x{exportTableAddress:X}");

                            IMAGE_EXPORT_DIRECTORY imageExportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(new IntPtr(exportTableAddress), typeof(IMAGE_EXPORT_DIRECTORY));
                            //Logger.Log($"ExportTable.NumberOfNames: {imageExportDirectory.NumberOfNames}");

                            for (int i = 0; i < imageExportDirectory.NumberOfNames; i++) {
                                long functionNameAddressPtr = baseAddress.ToInt64() + (uint)(imageExportDirectory.AddressOfNames + i * sizeof(uint));
                                //Logger.Log($"functionNameAddressPtr = {functionNameAddressPtr:X}");

                                long functionNameAddress = baseAddress.ToInt64() + Marshal.ReadInt32(new IntPtr(functionNameAddressPtr));
                                //Logger.Log($"functionNameAddress = {functionNameAddress:X}");

                                // Exported function name matches
                                string fnName = Marshal.PtrToStringAnsi(new IntPtr(functionNameAddress));
                                if (fnName.ToLower() == functionName.ToLower()) {

                                    long ordinalAddress = baseAddress.ToInt64() + imageExportDirectory.AddressOfNameOrdinals + i * sizeof(ushort);
                                    ushort ordinal = (ushort)(imageExportDirectory.Base + Marshal.ReadInt16(new IntPtr(ordinalAddress))); // Note: Ordinals start at the Base

                                    IntPtr pFunctionAddress = new IntPtr(baseAddress.ToInt64() + imageExportDirectory.AddressOfFunctions + (ordinal - imageExportDirectory.Base) * sizeof(uint));
                                    int virtualFunctionAddress = Marshal.ReadInt32(pFunctionAddress);
                                    IntPtr functionAddress = new IntPtr(baseAddress.ToInt64() + virtualFunctionAddress);

                                    if (functionAddress != pNativeAddress) {
                                        Logger.Log($"In-memory export table for {dllName} has function {functionName} pointing to 0x{functionAddress:X} but expected it to point to native 0x{pNativeAddress:X}");
                                        //throw new Exception("In-memory export table is corrupted somehow");
                                    }

                                    MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
                                    if (!VirtualQueryEx(Process.GetCurrentProcess().Handle, baseAddress, ref memInfo, (uint)Marshal.SizeOf(memInfo))) {
                                        throw new Exception($"Unable to query for address information at 0x{baseAddress:X}");
                                    }

                                    // Find a spot to put the call function
                                    // NOTE: We basically are throwing this in the beginning of the PE headers
                                    int forwardFunctionOffset = TRAMPOLINE_FUNCTION_OFFSETS[dllNameLower]; // throw it in the PE just after the sections list
                                    IntPtr pForwardFunction = IntPtr.Add(baseAddress, forwardFunctionOffset);

                                    // TODO: Make sure this is true
                                    // Quick sanity check that we aren't overwriting anything...
                                    /*
                                    string existingData = Marshal.PtrToStringAnsi(pForwardFunction);
                                    if (existingData.Length > 0) {
                                        throw new Exception($"Overwriting data in .rdata at address 0x{forwardFunctionOffset:X} (Absolute: 0x{pForwardFunction:X}): '{existingData}'");
                                    }
                                    */

                                    AllowMemoryWrite(pForwardFunction, PAGE_EXECUTE_READWRITE, () => {

                                        // Build out our x64 trampoline function, assuming the target function address is 0xDEADCAFEDEADBEEF
                                        /*
                                         * 68 {EF BE AD DE}             push 0xDEADBEEF
                                         * C7 44 24 04 {EF BE AD DE}    move [rsp+4] 0xDEADCAFE
                                         * C3                           ret
                                         */

                                        uint lowerVal = (uint)(interceptorFunctionAddress.ToInt64() & 0x00000000FFFFFFFF);
                                        var lower = BitConverter.GetBytes(lowerVal);
                                        uint upperVal = (uint)(interceptorFunctionAddress.ToInt64() >> 32);
                                        var upper = BitConverter.GetBytes(upperVal);

                                        var callForwardFunctionAssembly = new List<byte> { };
                                        callForwardFunctionAssembly.AddRange(new byte[] { 0x68 });
                                        callForwardFunctionAssembly.AddRange(lower);
                                        callForwardFunctionAssembly.AddRange(new byte[] { 0xC7, 0x44, 0x24, 0x04 });
                                        callForwardFunctionAssembly.AddRange(upper);
                                        callForwardFunctionAssembly.AddRange(new byte[] { 0xC3 });

                                        var hex = new StringBuilder();
                                        foreach (var b in callForwardFunctionAssembly) {
                                            hex.Append($"0x{b:X2} ");
                                        }
                                        Logger.Log($"{hex}", Logger.LogLevel.TRACE);

                                        Marshal.Copy(callForwardFunctionAssembly.ToArray(), 0, pForwardFunction, callForwardFunctionAssembly.Count);
                                        TRAMPOLINE_FUNCTION_OFFSETS[dllNameLower] += callForwardFunctionAssembly.Count;

                                        Logger.Log($"Wrote PATCH to 0x{pForwardFunction:X}", Logger.LogLevel.TRACE);
                                    });

                                    AllowMemoryWrite(pFunctionAddress, 0, () => {
                                        Logger.Log($"Patching export to be hijacked function function. (BaseAddress: 0x{baseAddress:X} RelativeAddress: 0x{forwardFunctionOffset:X} AbsoluteAddress: 0x{interceptorFunctionAddress:X}", Logger.LogLevel.TRACE);
                                        Marshal.WriteInt32(pFunctionAddress, forwardFunctionOffset);
                                    });

                                    Logger.Log($"Patched export function (AddressPtr: 0x{pFunctionAddress:X} VirtualAddress: 0x{virtualFunctionAddress:X} RealAddress: 0x{functionAddress:X} Ordinal: 0x{ordinal:X} Name: '{functionName}'')", Logger.LogLevel.TRACE);
                                    break;
                                }

                            }
                        }
                    }

                } else {
                    Logger.Log($"Skipping self", Logger.LogLevel.TRACE);
                }
                flink = entry.InLoadOrderLinks.Flink;
                entry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(flink, typeof(LDR_DATA_TABLE_ENTRY));
            }

            Logger.Log("-------------------------", Logger.LogLevel.TRACE);
            return pNativeAddress;
        }

        // Temporarily sets the RWX flags on virtual memory blocks while executing an action
        private static void AllowMemoryWrite(IntPtr memoryAddress, uint flNewProtect, Action action) {

            MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
            if (!VirtualQueryEx(Process.GetCurrentProcess().Handle, memoryAddress, ref memInfo, (uint)Marshal.SizeOf(memInfo))) {
                throw new Exception($"Unable to query for address information at 0x{memoryAddress:X}");
            }

            // If user didn't provide a flNewProtect we will restore back to the current value
            if (flNewProtect == 0) {
                flNewProtect = memInfo.Protect;
            }

            // Make memory writable
            if (!VirtualProtect(memInfo.BaseAddress, (UIntPtr)memInfo.RegionSize.ToInt64(), PAGE_READWRITE, out _)) {
                throw new Exception($"Unable to unprotect virtual memory");
            }

            action();

            // Restore protection
            if (!VirtualProtect(memInfo.BaseAddress, (UIntPtr)memInfo.RegionSize.ToInt64(), flNewProtect, out _)) {
                throw new Exception($"Unable to unprotect virtual memory");
            }

        }
    }
}
