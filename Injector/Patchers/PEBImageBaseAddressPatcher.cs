using Silverton.Core.Interop;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Silverton.Core.Interop.NativeBridge;

namespace Silverton.Injector.Patchers {

    // Override PEB ImageBaseAddress in order for FormatMessage / RtlFindMessage to find messages (for cmd.exe)
    internal class PEBImageBaseAddressPatcher : IDisposable {

        private long originalImageBaseAddress;

        public PEBImageBaseAddressPatcher(long dllBaseAddress) {
            IntPtr pebAddress = NativeBridge.GetPEBAddress(Process.GetCurrentProcess().Handle);
            PEB peb = (PEB)Marshal.PtrToStructure(pebAddress, typeof(PEB));
            originalImageBaseAddress = peb.ImageBaseAddress.ToInt64();
            Marshal.WriteInt64(IntPtr.Add(pebAddress, Marshal.OffsetOf<PEB>("ImageBaseAddress").ToInt32()), dllBaseAddress);
        }

        public void Dispose() {
            IntPtr pebAddress = NativeBridge.GetPEBAddress(Process.GetCurrentProcess().Handle);
            PEB peb = (PEB)Marshal.PtrToStructure(pebAddress, typeof(PEB));
            Marshal.WriteInt64(IntPtr.Add(pebAddress, Marshal.OffsetOf<PEB>("ImageBaseAddress").ToInt32()), originalImageBaseAddress);
        }
    }
 }
