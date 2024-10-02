using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Silverton.Core.Interop;
using Silverton.Core.Log;

namespace Silverton.Injector.Patchers {

    // Allows for our injected program arguments to be patched so injected code retrieves our intended arguments
    // Patches .NET Environment.GetCommandLineArgs()
    // Patches GetCommandLineW() & GetCommandLineA()
    // Patches RTL_USER_PROCESS_PARAMETERS ImagePathName & CommandLine
    // Portions based on https://github.com/nettitude/RunPE/blob/main/RunPE/Patchers/ArgumentPatcher.cs
    public class ArgumentPatcher : IDisposable
    {
        private const int PEB_RTL_USER_PROCESS_PARAMETERS_OFFSET = 0x20; // Offset into the PEB that the RTL_USER_PROCESS_PARAMETERS pointer sits at
        private const int RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET = 0x70; // Offset into the RTL_USER_PROCESS_PARAMETERS that the CommandLine sits at https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameter
        private const int RTL_USER_PROCESS_PARAMETERS_MAX_LENGTH_OFFSET = 2;
        private const int  RTL_USER_PROCESS_PARAMETERS_IMAGE_OFFSET = 0x60; // Offset into the RTL_USER_PROCESS_PARAMETERS that the CommandLine sits at https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters
        private const int  UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET = 0x8; // Offset into the UNICODE_STRING struct that the string pointer sits at https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string

        private IntPtr _ppCommandLineString;
        private IntPtr _ppImageString;
        private IntPtr _pLength;
        private IntPtr _pMaxLength;

        public ArgumentPatcher(string filename, string[] args) {

            var newCommandLineString = string.Join(" ", args);

            PatchRtlUserProcessParameters(filename, newCommandLineString);
            PatchGetCommandLine(newCommandLineString);
            PatchCLREnvironment(newCommandLineString);

            Logger.Log($"Overwrote GetCommandLine(): {newCommandLineString}", Logger.LogLevel.TRACE);
        }

        public void Dispose() {
            // TODO: Restore
        }

        // .NET CLR 8.0 `Environment.GetCommandLineArgs()` reads from a value read at startup
        private void PatchCLREnvironment(string newCommandLineString) {
            //s_commandLineArgs

            var type = typeof(Environment);
            var property = type.GetField("s_commandLineArgs", BindingFlags.Static | BindingFlags.NonPublic)!;
            if (property != null) {
                property.SetValue(null, null);
                Logger.Log("Set .NET CLR Environment.s_commandLineArgs to null", Logger.LogLevel.TRACE);
            }
        }

        // .NET CLR caches the GetCommandLineW() pointer on startup, therefore we need to override the actual memory at the address GetCommandLine() returns
        private void PatchGetCommandLine(string newCommandLineString) {

            // GetCommandLineW
            var pOldCommandLine = NativeBridge.GetCommandLineW();
            var oldCommandLine = Marshal.PtrToStringUni(pOldCommandLine);
            var newCommandLineBytes = Encoding.Unicode.GetBytes(newCommandLineString + "\0");
            if (newCommandLineString.Length > oldCommandLine.Length) {
                throw new Exception("Desired command line is longer than hijacked command line.  This should not be possible given that the hijacked command line contains the desired command line inside it");
            }
            Marshal.Copy(newCommandLineBytes, 0, pOldCommandLine, newCommandLineBytes.Length);

            // GetCommandLineA
            pOldCommandLine = NativeBridge.GetCommandLineA();
            oldCommandLine = Marshal.PtrToStringAnsi(pOldCommandLine);
            newCommandLineBytes = Encoding.Convert(Encoding.Unicode, Encoding.ASCII, Encoding.Unicode.GetBytes(newCommandLineString + "\0"));
            if (newCommandLineString.Length > oldCommandLine.Length) {
                throw new Exception("Desired command line is longer than hijacked command line.  This should not be possible given that the hijacked command line contains the desired command line inside it");
            }
            Marshal.Copy(newCommandLineBytes, 0, pOldCommandLine, newCommandLineBytes.Length);
        }

        // Patch the PEB RTL_USER_PROCESS_PARAMETERS ImagePathName & CommandLine
        private void PatchRtlUserProcessParameters(string filename, string newCommandLineString) {

            var pPEB = NativeBridge.GetPEBAddress(Process.GetCurrentProcess().Handle);
            if (pPEB == IntPtr.Zero) {
                throw new Exception("Unable to find PEB");
            }

            GetPebCommandLineAndImagePointers(pPEB, out _ppCommandLineString, out _ppImageString, out _pLength, out _pMaxLength);

            var pNewCommandLineString = Marshal.StringToHGlobalUni(newCommandLineString);
            var pNewImageString = Marshal.StringToHGlobalUni(filename);
            if (!PatchAddress(_ppCommandLineString, pNewCommandLineString)) {
                throw new Exception("Could not patch PEB RTL_USER_PROCESS_PARAMETERS CommandLine field");
            }

            if (!PatchAddress(_ppImageString, pNewImageString)) {
                throw new Exception("Could not patch PEB RTL_USER_PROCESS_PARAMETERS ImagePathName field");
            }

            Marshal.WriteInt16(_pLength, 0, (short)newCommandLineString.Length);
            Marshal.WriteInt16(_pMaxLength, 0, (short)newCommandLineString.Length);
        }

        private static void GetPebCommandLineAndImagePointers(IntPtr pPEB, out IntPtr ppCommandLineString,
            out IntPtr ppImageString, out IntPtr pCommandLineLength, out IntPtr pCommandLineMaxLength){

            var ppRtlUserProcessParams = (IntPtr) (pPEB.ToInt64() + PEB_RTL_USER_PROCESS_PARAMETERS_OFFSET);

            var pRtlUserProcessParams = Marshal.ReadInt64(ppRtlUserProcessParams);

            ppCommandLineString = (IntPtr) pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET +
                                  UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET;
            ppImageString = (IntPtr) pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_IMAGE_OFFSET +
                            UNICODE_STRING_STRUCT_STRING_POINTER_OFFSET;
            pCommandLineLength = (IntPtr) pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET;
            pCommandLineMaxLength = (IntPtr) pRtlUserProcessParams + RTL_USER_PROCESS_PARAMETERS_COMMANDLINE_OFFSET +
                                    RTL_USER_PROCESS_PARAMETERS_MAX_LENGTH_OFFSET;
        }

        private static bool PatchAddress(IntPtr pAddress, IntPtr newValue) {
            var result = NativeBridge.VirtualProtect(pAddress, (UIntPtr)IntPtr.Size,
                NativeBridge.PAGE_EXECUTE_READWRITE, out var oldProtect);
            if (!result) {
                throw new Exception($"Unable to change memory protections to RW for modification on address: 0x{pAddress:X}: 0x{NativeBridge.GetLastError():X}");
            }

            Marshal.WriteIntPtr(pAddress, newValue);
            result = NativeBridge.VirtualProtect(pAddress, (UIntPtr)IntPtr.Size, oldProtect, out _);
            if (!result) {
                throw new Exception($"Unable to revert memory protections to RW for modification on address: 0x{pAddress:X}: 0x{NativeBridge.GetLastError():X}");
            }

            Logger.Log($"Patched pointer at 0x{pAddress:X} to 0x{newValue:X}", Logger.LogLevel.TRACE);

            return true;
        }

    }
}