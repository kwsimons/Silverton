using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Silverton.Core.Interop.NativeBridge;

namespace Silverton.Injector.Patchers {

    // Patch the LdrpImageEntry.FullDllName field which is read by LdrGetDllFullName/GetModuleFileNameW when NULL is passed in
    // This is necessary as the .NET runtime uses this in exe_start() to find the main .NET dll to invoke
    internal class LdrpImageEntryFullDllNamePatcher : IDisposable {

        private UNICODE_STRING originalValue;

        public LdrpImageEntryFullDllNamePatcher(string exePath) {
            IntPtr pFirstLdrEntry = getLdrInLoadOrderLinksFlink();
            LDR_DATA_TABLE_ENTRY entry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(pFirstLdrEntry, typeof(LDR_DATA_TABLE_ENTRY));
            originalValue = entry.FullDllName;
            entry.FullDllName = new UNICODE_STRING(exePath);
            Marshal.StructureToPtr(entry, pFirstLdrEntry, true);
        }

        public void Dispose() {
            IntPtr pFirstLdrEntry = getLdrInLoadOrderLinksFlink();
            LDR_DATA_TABLE_ENTRY entry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(pFirstLdrEntry, typeof(LDR_DATA_TABLE_ENTRY));
            entry.FullDllName = originalValue;
            Marshal.StructureToPtr(entry, pFirstLdrEntry, true);
        }

        private IntPtr getLdrInLoadOrderLinksFlink() {
            IntPtr pebAddress = GetPEBAddress(Process.GetCurrentProcess().Handle);
            PEB peb = (PEB)Marshal.PtrToStructure(pebAddress, typeof(PEB));
            PEB_LDR_DATA ldr = (PEB_LDR_DATA)Marshal.PtrToStructure(peb.Ldr, typeof(PEB_LDR_DATA));
            return ldr.InLoadOrderLinks.Flink;
        }
    }
}
