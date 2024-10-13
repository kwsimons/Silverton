using Silverton.Core.Interop;
using Silverton.Core.Log;
using Silverton.Interceptor;
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

/*
 * TODO:
 * [ ] Improve GetFullDllPath() logic
 */
namespace Silverton.Injector {

    // Responsible for resolving and loading Dlls, calling native LoadLibrary() where possible and falling back to our Dll injector otherwise.
    public class DllLoader {

        private IntPtr nativeLoadLibraryExWAddress;
        private string searchPath;
        private NativeFunctionInvoker functionInvoker;

        public DllLoader(string searchPath, IntPtr nativeLoadLibraryExWAddress, NativeFunctionInvoker functionInvoker) {
            this.searchPath = searchPath;
            this.nativeLoadLibraryExWAddress = nativeLoadLibraryExWAddress;
            //this.nativeLoadLibraryExW = Marshal.GetDelegateForFunctionPointer<LoadLibraryExW>(nativeLoadLibraryExWAddress);
            this.functionInvoker = functionInvoker;
            NativeBridge.SetDllDirectory(searchPath);
        }

        public IntPtr LoadLibrary(string dllName, int dwFlags) {

            string dllFullPath = GetFullDllPath(dllName, dwFlags);

            int errorCode = 0;
            bool alreadyLoaded = false;
            IntPtr moduleHandle;

            try {
                // Already loaded
                moduleHandle = NativeBridge.GetModuleHandle(dllName);
                errorCode = Marshal.GetLastWin32Error();
                if (moduleHandle != IntPtr.Zero) {
                    // Logger.Log($"{dllFullPath} already loaded");
                    // NOTE: We still want to call LoadLibrary() so we increment the reference count so it is not unloaded
                    alreadyLoaded = true;
                }
            } catch (Exception e) {
                Logger.Log($"{e.Message}\n{e.ToString()}", Logger.LogLevel.ERROR);
                throw new Win32Exception(0x123);
            }

            // Natively load it
            {
                // NOTE: We do NOT want to cache this (I think that mswsock redirects the DLL internals)
                var nativeLoadLibraryExW = Marshal.GetDelegateForFunctionPointer<LoadLibraryExW>(nativeLoadLibraryExWAddress);
                moduleHandle = nativeLoadLibraryExW(dllName, IntPtr.Zero, dwFlags);
                errorCode = Marshal.GetLastWin32Error();
                if (moduleHandle != IntPtr.Zero) {
                    if (!alreadyLoaded) {
                        Logger.Log($"Natively loaded {dllName}");

                        // Dll loaded callbacks
                        PostDllLoadCallback(Path.GetFileName(dllFullPath));
                    }
                    return moduleHandle;
                }

                // If the file exists and we get a known code integrity error then we know it was blocked and we need to inject it
                // 0x03 = ERROR_PATH_NOT_FOUND
                // 0x05 = ERROR_ACCESS_DENIED
                // 0x7E = ERROR_MOD_NOT_FOUND
                if ((errorCode == 0x03 || errorCode == 0x05 || errorCode == 0x7E) && File.Exists(dllFullPath)) {
                    Logger.Log($"OS code integrity check failure (0x{errorCode:X}): {dllName}");
                } else {
                    //Logger.Log($"Could not natively load library for {dllName}", Logger.LogLevel.ERROR);
                    throw new Win32Exception(errorCode, $"Could not natively load library for {dllName}: 0x{errorCode:X}");
                }
            }

            // Inject it
            {
                if (!File.Exists(dllFullPath)) {
                    throw new Win32Exception(0x2, "File not found"); // File not found
                }

                // Inject it
                try {
                    return InjectLibrary(dllFullPath, dwFlags).InMemoryPE.BaseAddress;
                } catch (Win32Exception e) {
                    throw new Win32Exception(e.NativeErrorCode, $"Could not inject library {dllFullPath}: {e.Message}");
                } catch (Exception e) {
                    Logger.Log($"{e.Message}\n{e.ToString()}", Logger.LogLevel.ERROR);
                    throw new Win32Exception(0x789);
                }
            }
        }

        /*
         TODO: This isn't perfectly mimicking the native logic.

         https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
           The folder from which the application loaded.
           The folder specified by the lpPathName parameter of SetDllDirectory.
           The system folder.
           The 16-bit system folder.
           The Windows folder.
           The directories listed in the PATH environment variable.
         */
        private string GetFullDllPath(string dllName, int dwFlags) {
            //Logger.Log($"GetFullDllPath({dllName})");

            if (Path.IsPathRooted(dllName)) {
                return dllName;
            }

            // The folder from which the application loaded.
            string filePath = Path.Combine(searchPath, dllName);
            if (File.Exists(filePath)) {
                return filePath;
            }

            // The system folder.
            return Environment.SystemDirectory + @"\" + dllName;
        }

        private InjectedPE InjectLibrary(string fullPath, int dwFlags) {

            if (!File.Exists(fullPath)) {
                // ERROR_MOD_NOT_FOUND: The specified module could not be found.
                throw new Win32Exception(0x7E, $"File not found: {fullPath}");
            }

            // Load the DLL into memory
            var inMemoryPE = InMemoryPE.LoadDll(fullPath, dwFlags, this);

            // Inject the dll
            var injectedPE = InjectedPE.Inject(inMemoryPE, fullPath, this.functionInvoker);

            // Dll loaded callbacks
            PostDllLoadCallback(Path.GetFileName(fullPath));

            return injectedPE;
        }

        private void PostDllLoadCallback(string dllName) {
            NativeFunctionInterceptor.InstallCustomDllIntercepts(dllName);
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        public delegate IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, int dwFlags);
    }
}
