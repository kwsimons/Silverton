using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security;
using System.Text;
using Silverton.Core.Image;
using Silverton.Core.Log;

namespace Silverton.Core.Interop {

    // Native interop APIs and data structures
    public static class NativeBridge {

        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_WRITECOPY = 0x08;

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x00008000;

        public const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        public const uint IMAGE_SCN_MEM_READ = 0x40000000;
        public const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

        public const UInt32 DLL_PROCESS_DETACH = 0;
        public const UInt32 DLL_PROCESS_ATTACH = 1;
        public const UInt32 DLL_THREAD_ATTACH = 2;
        public const UInt32 DLL_THREAD_DETACH = 3;

        public const int STD_INPUT_HANDLE = -10;
        public const int STD_OUTPUT_HANDLE = -11;
        public const int STD_ERROR_HANDLE = -12;

        [Flags]
        public enum LoadLibraryFlags : uint {
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }

        public static class StartUpFlags {
            public const int STARTF_USESTDHANDLES = 0x00000100;
        }

        public static class DuplicateHandleOptions {
            public const int DUPLICATE_CLOSE_SOURCE = 0x00000001;
            public const int DUPLICATE_SAME_ACCESS = 0x00000002;
            public const int DUPLICATE_SAME_ATTRIBUTES = 0x00000004;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION {
            public uint BaseOffset;
            public uint SizeOfBlock;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION {
            public int ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public int BasePriority;
            public IntPtr UniquePID;
            public IntPtr InheritedFromUniqueProcessId;
        }


        [StructLayout(LayoutKind.Explicit)]
        public struct PEB {
            [FieldOffset(0x2)]
            public byte BeingDebugged;
            [FieldOffset(0x10)]
            public IntPtr ImageBaseAddress;
            [FieldOffset(0x18)]
            public IntPtr Ldr;
            [FieldOffset(0xbc)]
            public uint NtGlobalFlag;
            [FieldOffset(0x7c4)]
            public uint NtGlobalFlag2;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct PEB_LDR_DATA {
            [FieldOffset(0x00)]
            public ulong Length;
            [FieldOffset(0x04)]
            public bool Initialized;
            [FieldOffset(0x08)]
            public IntPtr SsHandle;
            [FieldOffset(0x10)]
            public LIST_ENTRY InLoadOrderLinks; // 0x10
            [FieldOffset(0x20)]
            public LIST_ENTRY InMemoryOrderLinks; // 0x20
            [FieldOffset(0x30)]
            public LIST_ENTRY InInitializationOrderLinks; // 0x30
            [FieldOffset(0x40)]
            public IntPtr EntryInProgress;
            [FieldOffset(0x48)]
            public byte ShutdownInProgress;
            [FieldOffset(0x50)]
            public IntPtr ShutdownThreadId;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LIST_ENTRY {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CRITICAL_SECTION {
            IntPtr DebugInfo;
            long LockCount;
            long RecursionCount;
            IntPtr OwningThread;
            IntPtr LockSemaphore;
            ulong SpinCount;
        }
        public enum LDR_DATA_TABLE_ENTRY_FLAGS : uint {
            LDRP_PACKAGED_BINARY = 0x00000001,
            LDRP_MARKED_FOR_REMOVAL = 0x00000002,
            LDRP_IMAGE_DLL = 0x00000004,
            LDRP_LOAD_NOTIFICATIONS_SENT = 0x00000008,
            LDRP_TELEMETRY_ENTRY_PROCESSED = 0x00000010,
            LDRP_PROCESS_STATIC_IMPORT = 0x00000020,
            LDRP_IN_LEGACY_LISTS = 0x00000040,
            LDRP_IN_INDEXES = 0x00000080,
            LDRP_SHIM_DLL = 0x00000100,
            LDRP_IN_EXCEPTION_TABLE = 0x00000200,
            LDRP_LOAD_IN_PROGRESS = 0x00001000,
            LDRP_LOAD_CONFIG_PROCESSED = 0x00002000,
            LDRP_ENTRY_PROCESSED = 0x00004000,
            LDRP_PROTECT_DELAY_LOAD = 0x00008000,
            LDRP_DONT_CALL_FOR_THREADS = 0x00040000,
            LDRP_PROCESS_ATTACH_CALLED = 0x00080000,
            LDRP_PROCESS_ATTACH_FAILED = 0x00100000,
            LDRP_COR_DEFERRED_VALIDATE = 0x00200000,
            LDRP_COR_IMAGE = 0x00400000,
            LDRP_DONT_RELOCATE = 0x00800000,
            LDRP_COR_IL_ONLY = 0x01000000,
            LDRP_CHPE_IMAGE = 0x02000000,
            LDRP_CHPE_EMULATOR_IMAGE = 0x04000000,
            LDRP_REDIRECTED = 0x10000000,
            LDRP_COMPAT_DATABASE_PROCESSED = 0x80000000
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct LDR_DATA_TABLE_ENTRY {
            [FieldOffset(0)]
            public LIST_ENTRY InLoadOrderLinks;
            [FieldOffset(0x10)]
            public LIST_ENTRY InMemoryOrderLinks;
            [FieldOffset(0x20)]
            public LIST_ENTRY InInitializationOrderLinks;
            [FieldOffset(0x30)]
            public IntPtr DllBase;
            [FieldOffset(0x38)]
            public IntPtr EntryPoint;
            [FieldOffset(0x40)]
            public uint SizeOfImage;
            [FieldOffset(0x48)]
            public UNICODE_STRING FullDllName;
            [FieldOffset(0x58)]
            public UNICODE_STRING BaseDllName;
            [FieldOffset(0x68)]
            public uint Flags;
            [FieldOffset(0x6C)]
            public ushort ObsoleteLoadCount;
            [FieldOffset(0x6E)]
            public ushort TlsIndex;
            [FieldOffset(0x70)]
            public LIST_ENTRY HashLinks;
            [FieldOffset(0x80)]
            public ulong TimeDateStamp;
            [FieldOffset(0x88)]
            public IntPtr  /* _ACTIVATION_CONTEXT* */ EntryPointActivationContext;
            [FieldOffset(0x90)]
            public IntPtr Lock; // 0x90
            [FieldOffset(0x98)]
            public IntPtr /* _LDR_DDAG_NODE* */ DdagNode; // 0x98
            [FieldOffset(0xA0)]
            public LIST_ENTRY NodeModuleLink; // 0xA0
            [FieldOffset(0xB0)]
            public IntPtr  /* _LDRP_LOAD_CONTEXT* */ LoadContext;
            [FieldOffset(0xB8)]
            public IntPtr ParentDllBase;
            [FieldOffset(0xC0)]
            public IntPtr SwitchBackContext;
            [FieldOffset(0xC8)]
            public RTL_BALANCED_NODE BaseAddressIndexNode;
            [FieldOffset(0xE0)]
            public RTL_BALANCED_NODE MappingInfoIndexNode;
            [FieldOffset(0xF8)]
            public ulong OriginalBase;
            [FieldOffset(0x100)]
            public LARGE_INTEGER LoadTime;
            [FieldOffset(0x108)]
            public ulong BaseNameHashValue;
            [FieldOffset(0x10C)]
            public LDR_DLL_LOAD_REASON LoadReason;
            [FieldOffset(0x110)]
            public uint ImplicitPathOptions;
            [FieldOffset(0x114)]
            public uint ReferenceCount;
            [FieldOffset(0x118)]
            public uint DependentLoadFlags;
            [FieldOffset(0x11c)]
            public byte SigningLevel;
            [FieldOffset(0x120)]
            public uint CheckSum;
            [FieldOffset(0x128)]
            public IntPtr ActivePatchImageBase;
            [FieldOffset(0x130)]
            public LDR_HOT_PATCH_STATE HotPatchState;
        }

        public enum LDR_DLL_LOAD_REASON {
            StaticDependency = 0,
            StaticForwarderDependency = 1,
            DynamicForwarderDependency = 2,
            DelayloadDependency = 3,
            DynamicLoad = 4,
            AsImageLoad = 5,
            AsDataLoad = 6,
            EnclavePrimary = 7,
            EnclaveDependency = 8,
            PatchImage = 9,
            Unknown = -1
        }

        public enum LDR_HOT_PATCH_STATE {
            LdrHotPatchBaseImage = 0,
            LdrHotPatchNotApplied = 1,
            LdrHotPatchAppliedReverse = 2,
            LdrHotPatchAppliedForward = 3,
            LdrHotPatchFailedToPatch = 4,
            LdrHotPatchStateMax = 5
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct LDR_DDAG_NODE {
            [FieldOffset(0)]
            public LIST_ENTRY Modules;
            [FieldOffset(0x10)]
            public IntPtr ServiceTagList;
            [FieldOffset(0x18)]
            public ulong LoadCount;
            [FieldOffset(0x1C)]
            public ulong LoadWhileUnloadingCount;
            [FieldOffset(0x20)]
            public ulong LowestLink;
            [FieldOffset(0x28)]
            public IntPtr Dependencies;
            [FieldOffset(0x30)]
            public IntPtr IncomingDependencies;
            [FieldOffset(0x38)]
            public LDR_DDAG_STATE State;
            [FieldOffset(0x40)]
            public IntPtr CondenseLink;
            [FieldOffset(0x48)]
            public ulong PreorderNumber;
        }

        public enum LDR_DDAG_STATE {
            LdrModulesMerged = -5,
            LdrModulesInitError = -4,
            LdrModulesSnapError = -3,
            LdrModulesUnloaded = -2,
            LdrModulesUnloading = -1,
            LdrModulesPlaceHolder = 0,
            LdrModulesMapping = 1,
            LdrModulesMapped = 2,
            LdrModulesWaitingForDependencies = 3,
            LdrModulesSnapping = 4,
            LdrModulesSnapped = 5,
            LdrModulesCondensed = 6,
            LdrModulesReadyToInit = 7,
            LdrModulesInitializing = 8,
            LdrModulesReadyToRun = 9
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct ImageTlsDirectory64 {
            [field: FieldOffset(0x00)]
            public IntPtr StartAddressOfRawData;
            [field: FieldOffset(0x08)]
            public IntPtr EndAddressOfRawData;
            [field: FieldOffset(0x10)]
            public IntPtr AddressOfIndex;
            [field: FieldOffset(0x18)]
            public IntPtr AddressOfCallBacks;
            [field: FieldOffset(0x20)]
            public uint SizeOfZeroFill;
            [field: FieldOffset(0x24)]
            public uint Characteristics;
        };

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_DEBUG_DIRECTORY {
            [FieldOffset(0)]
            public uint Characteristics;
            [FieldOffset(4)]
            public uint TimeDateStamp;
            [FieldOffset(8)]
            public ushort MajorVersion;
            [FieldOffset(10)]
            public ushort MinorVersion;
            [FieldOffset(12)]
            public uint Type;
            [FieldOffset(16)]
            public uint SizeOfData;
            [FieldOffset(20)]
            public uint AddressOfRawData;
            [FieldOffset(24)]
            public uint PointerToRawData;
        };

        [StructLayout(LayoutKind.Explicit)]
        public struct RSDS_PEB {
            [FieldOffset(0x00)]
            public uint CvSig;
            [FieldOffset(0x04)]
            public Guid Guid;
            [FieldOffset(0x14)]
            public uint Age;
            //[FieldOffset(0x18)]
            //public uint String;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct LARGE_INTEGER {
            [FieldOffset(0)]
            public int Low;
            [FieldOffset(4)]
            public int High;
            [FieldOffset(0)]
            public long QuadPart;

            public long ToInt64() {
                return ((long)this.High << 32) | (uint)this.Low;
            }

            public static LARGE_INTEGER FromInt64(long value) {
                return new LARGE_INTEGER {
                    Low = (int)(value),
                    High = (int)((value >> 32))
                };
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_BALANCED_NODE {
            public IntPtr /* RTL_BALANCED_NODE* */ Left;
            public IntPtr /* RTL_BALANCED_NODE* */ Right;
            public ulong ParentValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_RB_TREE {
            public IntPtr Root; // RTL_BALANCED_NODE
            public IntPtr Min; // RTL_BALANCED_NODE
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void SetLastError(uint dwErrorCode);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int ResumeThread(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CreateProcess(
            [MarshalAs(UnmanagedType.LPWStr)]
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            int dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

#nullable enable
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessW(
            [MarshalAs(UnmanagedType.LPWStr)]
            string? lpApplicationName,
            [MarshalAs(UnmanagedType.LPWStr)]
            string? lpCommandLine,
            IntPtr procSecAttrs,
            IntPtr threadSecAttrs,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPWStr)]
            string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );
#nullable disable

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int PsSetCreateThreadNotifyRoutine(
           IntPtr NotifyRoutine
        );

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessAsUserW(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            int dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcess,
            out IntPtr lpTargetHandle,
            int dwDesiredAccess,
            bool bInheritHandle,
            int dwOptions
        );

        [DllImport("kernel32.dll")]
        public static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, ref MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
            ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        public static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength, IntPtr returnLength);

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibraryA(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, int dwFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibraryExW(string lpLibFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool GetModuleHandleEx(uint dwFlags, string lpModuleName, out IntPtr phModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool GetModuleHandleExW(uint dwFlags, string lpModuleName, out IntPtr phModule);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint FormatMessage(uint dwFlags, IntPtr lpSource, uint dwMessageId, uint dwLanguageId, out string lpBuffer, uint nSize, IntPtr[] Arguments);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);


        [DllImport("ntdll.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern IntPtr LdrLoadDll(
            string DllPath,
            uint DllCharacteristics,
            ref UNICODE_STRING DllName,
            out IntPtr DllHandle
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, ulong ordinal);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr GetCommandLineA();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr GetCommandLineW();

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);

        [DllImport("kernel32")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
            IntPtr param, uint dwCreationFlags, ref IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpFlOldProtect);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [PreserveSig]
        public static extern uint GetModuleFileName(IntPtr hModule, StringBuilder lpFilename, [MarshalAs(UnmanagedType.U4)] int nSize);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFree(IntPtr pAddress, uint size, uint freeType);

        [DllImport("kernel32.dll")]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        public static extern uint WaitForMultipleObjects(uint nCount, IntPtr[] lpHandles, bool bWaitAll, uint dwMilliseconds);

        [DllImport("user32.dll")]
        public static extern uint  MsgWaitForMultipleObjects(uint nCount, IntPtr[] pHandles, bool bWaitAll, int dwMilliseconds, uint dwWakeMask);

        [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);

        public class QueueStatusFlags {
            public const uint QS_KEY = 0x0001;
            public const uint QS_MOUSEMOVE = 0x0002;
            public const uint QS_MOUSEBUTTON = 0x0004;
            public const uint QS_POSTMESSAGE = 0x0008;
            public const uint QS_TIMER = 0x0010;
            public const uint QS_PAINT = 0x0020;
            public const uint QS_SENDMESSAGE = 0x0040;
            public const uint QS_HOTKEY = 0x0080;
            public const uint QS_ALLPOSTMESSAGE = 0x0100;
            public const uint QS_EVENT = 0x02000;
            public const uint QS_MOUSE = QS_MOUSEMOVE | QS_MOUSEBUTTON;
            public const uint QS_INPUT = QS_MOUSE | QS_KEY;
            public const uint QS_ALLEVENTS = QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY;
            public const uint QS_ALLINPUT = QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY | QS_SENDMESSAGE;
        }

        public static class FormatMessageFlags {
            public const uint FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
            public const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
            public const uint FORMAT_MESSAGE_FROM_STRING = 0x00000400;
            public const uint FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
            public const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
            public const uint FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000;
            public const uint FORMAT_MESSAGE_MAX_WIDTH_MASK = 0x000000FF;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s) {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose() {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString() {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        public static IntPtr GetPEBAddress(IntPtr hProcess) {

            PROCESS_BASIC_INFORMATION processInformation = new PROCESS_BASIC_INFORMATION { };
            var result = NtQueryInformationProcess(hProcess, 0, ref processInformation, (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), IntPtr.Zero);

            if (result != 0) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return processInformation.PebAddress;
        }

        public static ulong CreateCacheKey(UNICODE_STRING BaseDllName) {
            ulong hash = 0;
            RtlHashUnicodeString(ref BaseDllName, true, 0, ref hash);
            hash &= (32 - 1); // LDR_HASH_TABLE_ENTRIES = 32
            return hash;
        }

        // Find LdrpHashTable address
        // https://github.com/DarthTon/Blackbone/blob/master/src/BlackBone/ManualMap/Native/NtLoader.cpp#L153
        public static IntPtr FindLdrpHashTable() {
            IntPtr pHead = IntPtr.Zero;
            IntPtr pEntry = IntPtr.Zero;
            IntPtr pCurrentEntry = IntPtr.Zero; // PLDR_DATA_TABLE_ENTRY2

            IntPtr pebAddress = GetPEBAddress(Process.GetCurrentProcess().Handle);
            PEB peb = (PEB)Marshal.PtrToStructure(pebAddress, typeof(PEB));
            PEB_LDR_DATA ldr = (PEB_LDR_DATA)Marshal.PtrToStructure(peb.Ldr, typeof(PEB_LDR_DATA));

            int offset = 0x20;
            pHead = peb.Ldr + offset; // InInitializationOrderLinks
            pEntry = ldr.InInitializationOrderLinks.Flink;

            do {
                pCurrentEntry = pEntry - offset;
                LDR_DATA_TABLE_ENTRY entry = (LDR_DATA_TABLE_ENTRY) Marshal.PtrToStructure(pCurrentEntry, typeof(LDR_DATA_TABLE_ENTRY));

                pEntry = entry.InInitializationOrderLinks.Flink;

                // ntdll.dll always is the first record in the hash table for it's hash
                if (entry.BaseDllName.ToString().ToLower() == "ntdll.dll") {
                    // Return the record *before* this first record, as it is the record in the actual LdrpHashTable
                    IntPtr pList = new IntPtr(entry.HashLinks.Blink.ToInt64() - (long)(CreateCacheKey(entry.BaseDllName) * (ulong)Marshal.SizeOf<LIST_ENTRY>()));
                    Logger.Log($"Found Hash table at 0x{pList:X} (0x{pList.ToInt64()-LoadLibrary("ntdll.dll").ToInt64():X})", Logger.LogLevel.TRACE);
                    return pList;
                }
                /*
                // Hashlinks points to itself
                IntPtr pHashLinks = (pCurrentEntry + 0x70);
                if (entry.HashLinks.Flink == pHashLinks) {
                    continue;
                }

                pList = entry.HashLinks.Flink;
                var blah = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(IntPtr.Subtract(entry.HashLinks.Flink, Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("HashLinks").ToInt32()), typeof(LDR_DATA_TABLE_ENTRY));
                Logger.Log($"{pList} {entry.BaseDllName} -> {blah.BaseDllName} ({CreateCacheKey(entry.BaseDllName)} -> {CreateCacheKey(blah.BaseDllName)})");
                LIST_ENTRY list = (LIST_ENTRY)Marshal.PtrToStructure(pList, typeof(LIST_ENTRY));

                // Last item
                if (list.Flink == pHashLinks) {
                    pList = new IntPtr(entry.HashLinks.Flink.ToInt64() - (long)(CreateCacheKey(entry.BaseDllName) * (ulong)Marshal.SizeOf<LIST_ENTRY>()));
                    Logger.Log($"Found Hash table at 0x{pList:X}", Logger.LogLevel.TRACE);
                    break;
                }
                */

            } while (pHead != pEntry);

            throw new Exception("Unable to find HashTable address");
        }

        // UWP won't allow importing from ntdll.dll
        public delegate int LdrUnlockLoaderLockDelegate(ulong flags, ulong cookie);
        public static int LdrUnlockLoaderLock(ulong flags, ulong cookie) {
            return GetDelegate<LdrUnlockLoaderLockDelegate>("ntdll.dll", "LdrUnlockLoaderLock")(flags, cookie);
        }

        // UWP won't allow importing from ntdll.dll
        public delegate int LdrLockLoaderLockDelegate(ulong Flags, ref ulong State, ref ulong Cookie);
        public static int LdrLockLoaderLock(ulong Flags, ref ulong State, ref ulong Cookie) {
            return GetDelegate<LdrLockLoaderLockDelegate>("ntdll.dll", "LdrLockLoaderLock")(Flags, ref State, ref Cookie);
        }

        // UWP won't allow importing from ntdll.dll
        public delegate int RtlRbInsertNodeExDelegate(IntPtr Tree, IntPtr Parent, bool Right, IntPtr Node);
        public static int RtlRbInsertNodeEx(IntPtr Tree, IntPtr Parent, bool Right, IntPtr Node) {
            return GetDelegate<RtlRbInsertNodeExDelegate>("ntdll.dll", "RtlRbInsertNodeEx")(Tree, Parent, Right, Node);
        }

        public delegate uint RtlHashUnicodeStringDelegate(ref UNICODE_STRING String, bool CaseInsensitive, ulong HashAlgorithm, ref ulong HashValue);
        public static uint RtlHashUnicodeString(ref UNICODE_STRING String, bool CaseInsensitive, ulong HashAlgorithm, ref ulong HashValue) {
            return GetDelegate<RtlHashUnicodeStringDelegate>("ntdll.dll", "RtlHashUnicodeString")(ref String, CaseInsensitive, HashAlgorithm, ref HashValue);
        }

        public static T GetDelegate<T>(string DllName, string FunctionName) {
            var moduleHandle = GetModuleHandle(DllName);
            if (moduleHandle == IntPtr.Zero) {
                Logger.Log($"{DllName} is not loaded, natively loading...");
                moduleHandle = LoadLibrary(DllName);
                if (moduleHandle == IntPtr.Zero) {
                    throw new Exception($"Cannot natively load the DLL {DllName} for method delegation");
                }
            }
            //Logger.Log($"moduleHandle 0x{moduleHandle:X} ({DllName})");
            var functionHandle = GetProcAddress(moduleHandle, FunctionName);
            if(functionHandle == IntPtr.Zero) {
                throw new Exception($"Cannot find {DllName}!{FunctionName}");
            }
            //Logger.Log($"functionHandle 0x{functionHandle:X} ({FunctionName})");
            return Marshal.GetDelegateForFunctionPointer<T>(functionHandle);
        }

        public static RTL_RB_TREE GetLdrpModuleBaseAddressIndex() {
            return (RTL_RB_TREE)Marshal.PtrToStructure(GetLdrpModuleBaseAddressIndexAddress(), typeof(RTL_RB_TREE));
        }

        public static void DumpMemoryAtAddress(IntPtr address) {
            byte[] bytes = new byte[256];
            for (int i = 0; i < bytes.Length; i++) {
                bytes[i] = Marshal.ReadByte(address + i);
            }
            for (int i = 0; i < bytes.Length; i++) {
                if (i % 16 == 0) {
                    Console.Write("\n");
                }
                Console.Write($"{bytes[i]:X2} ");
            }
            Console.Write("\n");
        }

        // TODO: Switch this to RtlAddFunctionTable ?
        delegate uint RtlInsertInvertedFunctionTableDelegate(IntPtr DllBaseAddress, uint SizeOfImage);
        public static uint RtlInsertInvertedFunctionTable(IntPtr DllBaseAddress, uint SizeOfImage) {
            var function = Marshal.GetDelegateForFunctionPointer<RtlInsertInvertedFunctionTableDelegate>(GetRtlInsertInvertedFunctionTableAddress());
            return function(DllBaseAddress, SizeOfImage);
        }

        delegate uint LdrpHandleTlsDataDelegate(IntPtr PEBLoaderDataTableEntryAddress);
        public static uint LdrpHandleTlsData(IntPtr PEBLoaderDataTableEntryAddress) {
            // calls ntdll!LdrpHandleTlsData 
            var function = Marshal.GetDelegateForFunctionPointer<LdrpHandleTlsDataDelegate>(GetLdrpHandleTlsDataAddress());
            return function(PEBLoaderDataTableEntryAddress);
        }

        delegate uint LdrpReleaseTlsEntryDelegate(IntPtr PEBLoaderDataTableEntryAddress, out IntPtr RemovedTlsEntry);
        public static uint LdrpReleaseTlsEntry(IntPtr PEBLoaderDataTableEntryAddress) {
            // calls ntdll!LdrpReleaseTlsEntry
            var function = Marshal.GetDelegateForFunctionPointer<LdrpReleaseTlsEntryDelegate>(GetLdrpReleaseTlsEntryAddress());
            var removedTlsEntry = IntPtr.Zero;
            return function(PEBLoaderDataTableEntryAddress, out removedTlsEntry);
        }

        public const string NTDLL_GUID_PC = "e9bf26fa-c25f-2ac5-9a4e-bbbc29569688"; // 10.0.22631.4169
        public const string NTDLL_GUID_XBOX_2864 = "dcb12335-6c21-d9d2-6072-ad27af83e1aa"; // 10.0.22621.2864 (Nov 2022)
        public const string NTDLL_GUID_XBOX_4908_4909 = "c30d51bc-364d-2253-0808-24ef4382db62"; // 10.0.25398.4909 & 10.0.25398.4908
        public const string NTDLL_GUID_XBOX_4478 = "4a9c1d0f-33d3-b2fd-ce7d-0e4c3e5c4941"; // 10.0.25398.4478

        // find ntdll!LdrpModuleBaseAddressIndex variable
        // TODO: Make this more portable: https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks/
        public static IntPtr GetLdrpModuleBaseAddressIndexAddress() {
            switch (GetDebugGuid("ntdll.dll")) {
                case NTDLL_GUID_PC:
                    return GetModuleHandle("ntdll.dll") + 0x187108;
                case NTDLL_GUID_XBOX_2864:
                    return GetModuleHandle("ntdll.dll") + 0x185008;
                case NTDLL_GUID_XBOX_4908_4909:
                case NTDLL_GUID_XBOX_4478:
                    return GetModuleHandle("ntdll.dll") + 0x196998;
            }
            throw new Exception($"Unknown Dll debug PDB GUID: {GetDebugGuid("ntdll.dll")}");
        }

        // find ntdll!RtlInsertInvertedFunctionTable method
        public static IntPtr GetRtlInsertInvertedFunctionTableAddress() {
            switch (GetDebugGuid("ntdll.dll")) {
                case NTDLL_GUID_PC:
                    return GetModuleHandle("ntdll.dll") + 0x2C0BC;
                case NTDLL_GUID_XBOX_2864:
                    return GetModuleHandle("ntdll.dll") + 0x2C2AC;
                case NTDLL_GUID_XBOX_4908_4909:
                case NTDLL_GUID_XBOX_4478:
                    return GetModuleHandle("ntdll.dll") + 0x2B854;
            }
            throw new Exception($"Unknown Dll debug PDB GUID: {GetDebugGuid("ntdll.dll")}");
        }

        // find ntdll!LdrpHandleTlsData method
        public static IntPtr GetLdrpHandleTlsDataAddress() {
            switch (GetDebugGuid("ntdll.dll")) {
                case NTDLL_GUID_PC:
                    return GetModuleHandle("ntdll.dll") + 0x44F8;
                case NTDLL_GUID_XBOX_2864:
                    return GetModuleHandle("ntdll.dll") + 0x4564;
                case NTDLL_GUID_XBOX_4908_4909:
                case NTDLL_GUID_XBOX_4478:
                    return GetModuleHandle("ntdll.dll") + 0x63F44;
            }
            throw new Exception($"Unknown Dll debug PDB GUID: {GetDebugGuid("ntdll.dll")}");
        }

        // find ntdll!LdrpReleaseTlsEntry method
        public static IntPtr GetLdrpReleaseTlsEntryAddress() {
            switch (GetDebugGuid("ntdll.dll")) {
                case NTDLL_GUID_PC:
                    return GetModuleHandle("ntdll.dll") + 0x7FEEC;
                case NTDLL_GUID_XBOX_2864:
                    return GetModuleHandle("ntdll.dll") + 0x7F7AC;
                case NTDLL_GUID_XBOX_4908_4909:
                    return GetModuleHandle("ntdll.dll") + 0x81DC0;
                case NTDLL_GUID_XBOX_4478:
                    return GetModuleHandle("ntdll.dll") + 0x81E20;
            }
            throw new Exception($"Unknown Dll debug PDB GUID: {GetDebugGuid("ntdll.dll")}");
        }

        /*
        // find ntdll!LdrpFindLoadedDllByAddress method
        public static IntPtr LdrpFindLoadedDllByAddress() {
            switch (GetDebugGuid("ntdll.dll")) {
                case NTDLL_GUID_PC:
                    return GetModuleHandle("ntdll.dll") + 0x8A80;
                case NTDLL_GUID_XBOX_4909:
                    return GetModuleHandle("ntdll.dll") + 0x63240;
                case NTDLL_GUID_XBOX_4478:
                    return GetModuleHandle("ntdll.dll") + 0x0; // TODO
            }
            throw new Exception($"Unknown Dll debug PDB GUID: {GetDebugGuid("ntdll.dll")}");
        }
        */

        public static String GetDebugGuid(string dllName) {
            IntPtr moduleHandle = GetModuleHandle(dllName);
            PEImage pe = PEImage.PEReader.ParseLoadedModule(moduleHandle);
            if (pe.OptionalHeader64.Debug.Size == 0) {
                throw new Exception($"No debug directory for {dllName}");
            }

            Logger.Log($"pe.OptionalHeader64.Debug.VirtualAddress = 0x{pe.OptionalHeader64.Debug.VirtualAddress:X}", Logger.LogLevel.TRACE);
            for (var pDebugDirectory = new IntPtr(moduleHandle.ToInt64() + pe.OptionalHeader64.Debug.VirtualAddress);
                pDebugDirectory.ToInt64() < (moduleHandle.ToInt64() + pe.OptionalHeader64.Debug.VirtualAddress + pe.OptionalHeader64.Debug.Size);
                pDebugDirectory += Marshal.SizeOf<IMAGE_DEBUG_DIRECTORY>()) {

                Logger.Log($"pDebugDirectory = 0x{pDebugDirectory:X}", Logger.LogLevel.TRACE);
                var debugDirectory = Marshal.PtrToStructure<IMAGE_DEBUG_DIRECTORY>(pDebugDirectory);

                Logger.Log($"debugDirectory.Characteristics = 0x{debugDirectory.Characteristics:X}", Logger.LogLevel.TRACE);
                Logger.Log($"debugDirectory.TimeDateStamp = 0x{debugDirectory.TimeDateStamp:X}", Logger.LogLevel.TRACE);
                Logger.Log($"debugDirectory.MajorVersion = 0x{debugDirectory.MajorVersion:X}", Logger.LogLevel.TRACE);
                Logger.Log($"debugDirectory.MinorVersion = 0x{debugDirectory.MinorVersion:X}", Logger.LogLevel.TRACE);
                Logger.Log($"debugDirectory.Type = 0x{debugDirectory.Type:X}", Logger.LogLevel.TRACE);
                Logger.Log($"debugDirectory.SizeOfData = 0x{debugDirectory.SizeOfData:X}", Logger.LogLevel.TRACE);
                Logger.Log($"debugDirectory.AddressOfRawData = 0x{debugDirectory.AddressOfRawData:X}", Logger.LogLevel.TRACE);
                Logger.Log($"debugDirectory.PointerToRawData = 0x{debugDirectory.PointerToRawData:X}", Logger.LogLevel.TRACE);

                if (debugDirectory.Type == 0x02) { // IMAGE_DEBUG_TYPE_CODEVIEW

                    var rsds = Marshal.PtrToStructure<RSDS_PEB>(new IntPtr(moduleHandle.ToInt64() + debugDirectory.AddressOfRawData));

                    if (rsds.CvSig != 0x53445352) {
                        throw new Exception("Expected CvSig 'RSDS'");
                    }
                    Logger.Log($"rsds.CvSig = 0x{rsds.CvSig:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"rsds.Age = 0x{rsds.Age:X}", Logger.LogLevel.TRACE);
                    Logger.Log($"rsds.Guid = {rsds.Guid}", Logger.LogLevel.TRACE);

                    return rsds.Guid.ToString();
                }
            }

            throw new Exception("Could not find IMAGE_DEBUG_TYPE_CODEVIEW in IMAGE_DEBUG_DIRECTORY");
        }

        public const int LOGON32_PROVIDER_DEFAULT = 0;
        public const int LOGON32_PROVIDER_VIRTUAL = 4;

        public const int LOGON32_LOGON_INTERACTIVE = 2;
        public const int LOGON32_LOGON_SERVICE = 5;

        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern IntPtr GetCurrentThreadId();

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", ExactSpelling = true)]
        public static extern bool OpenThreadToken(IntPtr ThreadHandle, UInt32 DesiredAccess, Boolean OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr hToken, uint tokenInformationClass, IntPtr lpData, uint tokenInformationLength, out uint returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpsystemname, string lpname, ref LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, int dwLogonType, int dwLogonProvider, out SafeAccessTokenHandle phToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeName(
            string lpSystemName,
            ref LUID lpLuid,
            StringBuilder lpName,
            ref int cchName);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref UPDATE_TOKEN_PRIVILEGES NewState, uint Bufferlength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern bool PrivilegeCheck(IntPtr ClientToken, ref PRIVILEGE_SET RequiredPrivileges, out bool pfResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint AllocateAndInitializeSid
        (
            ref SID_IDENTIFIER_AUTHORITY siaNtAuthority,
            byte nSubAuthorityCount,
            uint dwSubAuthority0,
            uint dwSubAuthority1,
            uint dwSubAuthority2,
            uint dwSubAuthority3,
            uint dwSubAuthority4,
            uint dwSubAuthority5,
            uint dwSubAuthority6,
            uint dwSubAuthority7,
            out IntPtr pSid
        );

        [DllImport("advapi32.dll")]
        public static extern long LsaClose(IntPtr objectHandle);

        [DllImport("advapi32.dll")]
        public static extern long LsaNtStatusToWinError(long status);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle, IntPtr AccountSid,
            LSA_UNICODE_STRING[] UserRights,
            long CountOfRights);

        [DllImport("advapi32.dll", PreserveSig = true)]
        public static extern uint LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaOpenPolicy(
           ref LSA_UNICODE_STRING SystemName,
           ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
           uint DesiredAccess,
           out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint LsaManageSidNameMapping(
            LSA_SID_NAME_MAPPING_OPERATION_TYPE OperationType,
            IntPtr OperationInput,
            out IntPtr OperationOutput);

        [DllImport("advapi32.dll")]
        public static extern int LsaFreeMemory(IntPtr Buffer);

        public delegate IntPtr OpenEventLogDelegate(string lpUNCServerName, string lpSourceName);
        public static IntPtr OpenEventLog(string lpUNCServerName, string lpSourceName) {
            return GetDelegate<OpenEventLogDelegate>("advapi32.dll", "OpenEventLogA")(lpUNCServerName, lpSourceName);
        }

        public delegate bool ReadEventLogDelegate(
            IntPtr hEventLog,
            READ_EVENTLOG_FLAGS dwReadFlags,
            uint dwRecordOffset,
            IntPtr lpBuffer,
            uint nNumberOfBytesToRead,
            ref uint pnBytesRead,
            ref uint pnMinNumberOfBytesNeeded);
        public static bool ReadEventLog(
            IntPtr hEventLog,
            READ_EVENTLOG_FLAGS dwReadFlags,
            uint dwRecordOffset,
            IntPtr lpBuffer,
            uint nNumberOfBytesToRead,
            ref uint pnBytesRead,
            ref uint pnMinNumberOfBytesNeeded) {
            return GetDelegate<ReadEventLogDelegate>("advapi32.dll", "ReadEventLogA")(hEventLog, dwReadFlags, dwRecordOffset, lpBuffer, nNumberOfBytesToRead, ref pnBytesRead, ref pnMinNumberOfBytesNeeded);
        }

        [Flags]
        public enum READ_EVENTLOG_FLAGS : uint {
            EVENTLOG_SEEK_READ = 0x0002,
            EVENTLOG_SEQUENTIAL_READ = 0x0001,
            EVENTLOG_FORWARDS_READ = 0x0004,
            EVENTLOG_BACKWARDS_READ = 0x0008,
            EVENTLOG_SEEK_FORWARDS = EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ,
            EVENTLOG_SEEK_BACKWARDS = EVENTLOG_SEEK_READ | EVENTLOG_BACKWARDS_READ,
            EVENTLOG_SEQUENTIAL_FORWARDS = EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ,
            EVENTLOG_SEQUENTIAL_BACKWARDS = EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct EVENTLOGRECORD {
            [FieldOffset(0x00)]
            public int Length;
            [FieldOffset(0x04)]
            public int Reserved;
            [FieldOffset(0x08)]
            public int RecordNumber;
            [FieldOffset(0x0c)]
            public int TimeGenerated;
            [FieldOffset(0x10)]
            public int TimeWritten;
            [FieldOffset(0x14)]
            public int EventID;
            [FieldOffset(0x18)]
            public short EventType;
            [FieldOffset(0x1a)]
            public short NumStrings;
            [FieldOffset(0x1c)]
            public short EventCategory;
            [FieldOffset(0x1e)]
            public short ReservedFlags;
            [FieldOffset(0x20)]
            public int ClosingRecordNumber;
            [FieldOffset(0x24)]
            public int StringOffset;
            [FieldOffset(0x28)]
            public int UserSidLength;
            [FieldOffset(0x2c)]
            public int UserSidOffset;
            [FieldOffset(0x30)]
            public int DataLength;
            [FieldOffset(0x34)]
            public int DataOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_SID_NAME_MAPPING_OPERATION_OUTPUT {
            public LSA_SID_NAME_MAPPING_OPERATION_ERROR ErrorCode;
        }
        public enum LSA_SID_NAME_MAPPING_OPERATION_ERROR {
            Success,
            NonMappingError,
            NameCollision,
            SidCollision,
            DomainNotFound,
            DomainSidPrefixMismatch = 6,
            MappingNotFound = 7
        }

        public enum LSA_SID_NAME_MAPPING_OPERATION_TYPE {
            Add,
            Remove,
            AddMultiple,
        }

        public const string VIRTUALUSER_DOMAIN = "VIRTUAL USERS";
        public const string VIRTUALUSER_GROUP_NAME = "ALL VIRTUAL USERS";

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LSA_SID_NAME_MAPPING_OPERATION_ADD_INPUT {
            public UNICODE_STRING DomainName;
            public UNICODE_STRING AccountName;
            public IntPtr Sid;
            public int Flags;
        }

        public enum AccountRightsConstants {
            SeBatchLogonRight,
            SeInteractiveLogonRight,
            SeNetworkLogonRight,
            SeRemoteInteractiveLogonRight,
            SeServiceLogonRight,

            SeDenyBatchLogonRight,
            SeDenyInteractiveLogonRight,
            SeDenyNetworkLogonRight,
            SeDenyRemoteInteractiveLogonRight,
            SeDenyServiceLogonRight,
        }

        public enum AccountPrivilegeConstants {
            SeAssignPrimaryTokenPrivilege,
            SeAuditPrivilege,
            SeBackupPrivilege,
            SeChangeNotifyPrivilege,
            SeCreateGlobalPrivilege,
            SeCreatePagefilePrivilege,
            SeCreatePermanentPrivilege,
            SeCreateSymbolicLinkPrivilege,
            SeCreateTokenPrivilege,
            SeDebugPrivilege,
            SeDelegateSessionUserImpersonatePrivilege,
            SeEnableDelegationPrivilege,
            SeImpersonatePrivilege,
            SeIncreaseBasePriorityPrivilege,
            SeIncreaseQuotaPrivilege,
            SeIncreaseWorkingSetPrivilege,
            SeLoadDriverPrivilege,
            SeLockMemoryPrivilege,
            SeMachineAccountPrivilege,
            SeManageVolumePrivilege,
            SeProfileSingleProcessPrivilege,
            SeRelabelPrivilege,
            SeRemoteShutdownPrivilege,
            SeRestorePrivilege,
            SeSecurityPrivilege,
            SeShutdownPrivilege,
            SeSyncAgentPrivilege,
            SeSystemEnvironmentPrivilege,
            SeSystemProfilePrivilege,
            SeSystemtimePrivilege,
            SeTakeOwnershipPrivilege,
            SeTcbPrivilege,
            SeTimeZonePrivilege,
            SeTrustedCredManAccessPrivilege,
            SeUndockPrivilege,
            SeUnsolicitedInputPrivilege,
        }

        [Flags]
        public enum LSA_AccessPolicy : long {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        public const int POLICY_ALL_ACCESS = (int)(
            LSA_AccessPolicy.POLICY_AUDIT_LOG_ADMIN |
            LSA_AccessPolicy.POLICY_CREATE_ACCOUNT |
            LSA_AccessPolicy.POLICY_CREATE_PRIVILEGE |
            LSA_AccessPolicy.POLICY_CREATE_SECRET |
            LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION |
            LSA_AccessPolicy.POLICY_LOOKUP_NAMES |
            LSA_AccessPolicy.POLICY_NOTIFICATION |
            LSA_AccessPolicy.POLICY_SERVER_ADMIN |
            LSA_AccessPolicy.POLICY_SET_AUDIT_REQUIREMENTS |
            LSA_AccessPolicy.POLICY_SET_DEFAULT_QUOTA_LIMITS |
            LSA_AccessPolicy.POLICY_TRUST_ADMIN |
            LSA_AccessPolicy.POLICY_VIEW_AUDIT_INFORMATION |
            LSA_AccessPolicy.POLICY_VIEW_LOCAL_INFORMATION
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_UNICODE_STRING {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_OBJECT_ATTRIBUTES {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_IDENTIFIER_AUTHORITY {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
            public byte[] Value;
        }

        public static readonly SID_IDENTIFIER_AUTHORITY SECURITY_NT_AUTHORITY = CreateAuthority(0, 0, 0, 0, 0, 5);

        private static SID_IDENTIFIER_AUTHORITY CreateAuthority(params byte[] auth) {
            Debug.Assert(auth.Length == 6);
            var res = new SID_IDENTIFIER_AUTHORITY();
            res.Value = auth;
            return res;
        }

        // UWP won't bind this
        /*
        public delegate uint PrivilegeCheckDelegate(IntPtr ClientToken, ref PRIVILEGE_SET RequiredPrivileges, out bool pfResult);
        public static uint PrivilegeCheck(IntPtr ClientToken, ref PRIVILEGE_SET RequiredPrivileges, out bool pfResult);
            return GetDelegate<PrivilegeCheckDelegate>("advapi32.dll", "PrivilegeCheck")(ClientToken, ref RequiredPrivileges, out pfResult);
        }
        */

        public class TokenPrivileges {
            public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
            public const uint STANDARD_RIGHTS_READ = 0x00020000;
            public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
            public const uint TOKEN_DUPLICATE = 0x0002;
            public const uint TOKEN_IMPERSONATE = 0x0004;
            public const uint TOKEN_QUERY = 0x0008;
            public const uint TOKEN_QUERY_SOURCE = 0x0010;
            public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
            public const uint TOKEN_ADJUST_GROUPS = 0x0040;
            public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
            public const uint TOKEN_ADJUST_SESSIONID = 0x0100;
            public const uint TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;
            public const uint TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
                                TOKEN_ASSIGN_PRIMARY |
                                TOKEN_DUPLICATE |
                                TOKEN_IMPERSONATE |
                                TOKEN_QUERY |
                                TOKEN_QUERY_SOURCE |
                                TOKEN_ADJUST_PRIVILEGES |
                                TOKEN_ADJUST_GROUPS |
                                TOKEN_ADJUST_DEFAULT |
                                TOKEN_ADJUST_SESSIONID;
        }
        public enum TOKEN_INFORMATION_CLASS : uint {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            TokenProcessTrustLevel,
            TokenPrivateNameSpace,
            TokenSingletonAttributes,
            TokenBnoIsolation,
            TokenChildProcessFlags,
            TokenIsLessPrivilegedAppContainer,
            TokenIsSandboxed,
            TokenIsAppSilo,
            TokenLoggingInformation,
            MaxTokenInfoClass
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PRIVILEGE_SET {
            public uint PrivilegeCount;
            public uint Control;  // use PRIVILEGE_SET_ALL_NECESSARY

            public static uint PRIVILEGE_SET_ALL_NECESSARY = 1;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privilege;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UPDATE_TOKEN_PRIVILEGES {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64 /* magic number */)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES {
            public LUID Luid;
            public uint Attributes;

            public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
            public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
            public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
            public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID {
            public uint LowPart;
            public int HighPart;
            public long ToInt64() {
                return ((long)this.HighPart << 32) | (uint)this.LowPart;
            }
        }

        public const ulong RPC_C_AUTHN_DEFAULT = 0xFFFFFFFFL; // The system default authentication service
        public const uint FWP_E_ALREADY_EXISTS = 0x80320009;
        public const uint RPC_ACCESS_DENIED = 0x5;

        // UWP won't allow importing from FWPUClnt.dll
        public delegate uint FwpmEngineOpen0Delegate(IntPtr serverName, uint authnService, IntPtr authIdentity, IntPtr session, ref IntPtr engineHandle);
        public static uint FwpmEngineOpen0(IntPtr serverName, uint authnService, IntPtr authIdentity, IntPtr session, ref IntPtr engineHandle) {
            return GetDelegate<FwpmEngineOpen0Delegate>("FWPUClnt.dll", "FwpmEngineOpen0")(serverName, authnService, authIdentity, session, ref engineHandle);
        }

        public delegate uint FwpmEngineClose0Delegate(IntPtr engineHandle);
        public static uint FwpmEngineClose0(IntPtr engineHandle) {
            return GetDelegate<FwpmEngineClose0Delegate>("FWPUClnt.dll", "FwpmEngineClose0")(engineHandle);
        }

        public delegate uint FwpmTransactionBegin0Delegate(IntPtr engineHandle, uint flags);
        public static uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags) {
            return GetDelegate<FwpmTransactionBegin0Delegate>("FWPUClnt.dll", "FwpmTransactionBegin0")(engineHandle, flags);
        }

        public delegate uint FwpmTransactionCommit0Delegate(IntPtr engineHandle);
        public static uint FwpmTransactionCommit0(IntPtr engineHandle) {
            return GetDelegate<FwpmTransactionCommit0Delegate>("FWPUClnt.dll", "FwpmTransactionCommit0")(engineHandle);
        }

        public delegate uint FwpmFilterAdd0Delegate(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, ref IntPtr id);
        public static uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, ref IntPtr id) {
            return GetDelegate<FwpmFilterAdd0Delegate>("FWPUClnt.dll", "FwpmFilterAdd0")(engineHandle, ref filter, sd, ref id);
        }

        public delegate uint FwpmProviderAdd0Delegate(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);
        public static uint FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd) {
            return GetDelegate<FwpmProviderAdd0Delegate>("FWPUClnt.dll", "FwpmProviderAdd0")(engineHandle, ref provider, sd);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct FWPM_FILTER0 {
            public Guid filterKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public FirewallFilterFlags flags;
            public IntPtr providerKey; // GUID*
            public FWP_BYTE_BLOB providerData;
            public Guid layerKey;
            public Guid subLayerKey;
            public FWP_VALUE0 weight;
            public int numFilterConditions;
            public IntPtr filterCondition; // FWPM_FILTER_CONDITION0* 
            public FWPM_ACTION0 action;
            public FWPM_FILTER0_UNION context;
            public IntPtr reserved; // GUID* 
            public ulong filterId;
            public FWP_VALUE0 effectiveWeight;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct FWPM_FILTER0_UNION {
            [FieldOffset(0)]
            public ulong rawContext;
            [FieldOffset(0)]
            public Guid providerContextKey;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct FWPM_ACTION0_UNION {
            [FieldOffset(0)]
            public Guid filterType;
            [FieldOffset(0)]
            public Guid calloutKey;
            [FieldOffset(0)]
            public byte bitmapIndex;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct FWPM_FILTER_CONDITION0 {
            public Guid fieldKey;
            public FWP_MATCH_TYPE matchType;
            public FWP_CONDITION_VALUE0 conditionValue;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct FWP_CONDITION_VALUE0 {
            public FWP_DATA_TYPE type;
            public FWP_CONDITION_VALUE0_UNION anonymous;
        }

        [StructLayoutAttribute(LayoutKind.Explicit)]
        public struct FWP_CONDITION_VALUE0_UNION {
            [FieldOffsetAttribute(0)]
            public byte uint8;
            [FieldOffsetAttribute(0)]
            public ushort uint16;
            [FieldOffsetAttribute(0)]
            public int uint32;
            [FieldOffsetAttribute(0)]
            public System.IntPtr uint64;
            [FieldOffsetAttribute(0)]
            public byte int8;
            [FieldOffsetAttribute(0)]
            public short int16;
            [FieldOffsetAttribute(0)]
            public int int32;
            [FieldOffsetAttribute(0)]
            public System.IntPtr int64;
            [FieldOffsetAttribute(0)]
            public float float32;
            [FieldOffsetAttribute(0)]
            public System.IntPtr double64;
            [FieldOffsetAttribute(0)]
            public System.IntPtr byteArray16;
            [FieldOffsetAttribute(0)]
            public System.IntPtr byteBlob;
            [FieldOffsetAttribute(0)]
            public System.IntPtr sid;
            [FieldOffsetAttribute(0)]
            public System.IntPtr sd;
            [FieldOffsetAttribute(0)]
            public System.IntPtr tokenInformation;
            [FieldOffsetAttribute(0)]
            public System.IntPtr tokenAccessInformation;
            [FieldOffsetAttribute(0)]
            public System.IntPtr unicodeString;
            [FieldOffsetAttribute(0)]
            public System.IntPtr byteArray6;
            [FieldOffsetAttribute(0)]
            public System.IntPtr v4AddrMask;
            [FieldOffsetAttribute(0)]
            public System.IntPtr v6AddrMask;
            [FieldOffsetAttribute(0)]
            public System.IntPtr rangeValue;
        }

        public enum FWP_DATA_TYPE : int {
            FWP_EMPTY = 0,
            FWP_UINT8 = 1,
            FWP_UINT16 = 2,
            FWP_UINT32 = 3,
            FWP_UINT64 = 4,
            FWP_INT8 = 5,
            FWP_INT16 = 6,
            FWP_INT32 = 7,
            FWP_INT64 = 8,
            FWP_FLOAT = 9,
            FWP_DOUBLE = 10,
            FWP_BYTE_ARRAY16_TYPE = 11,
            FWP_BYTE_BLOB_TYPE = 12,
            FWP_SID = 13,
            FWP_SECURITY_DESCRIPTOR_TYPE = 14,
            FWP_TOKEN_INFORMATION_TYPE = 15,
            FWP_TOKEN_ACCESS_INFORMATION_TYPE = 16,

            /// FWP_UNICODE_STRING_TYPE -> 17
            FWP_UNICODE_STRING_TYPE = 17,

            /// FWP_BYTE_ARRAY6_TYPE -> 18
            FWP_BYTE_ARRAY6_TYPE = 18,

            /// FWP_SINGLE_DATA_TYPE_MAX -> 0xff
            FWP_SINGLE_DATA_TYPE_MAX = 255,

            /// FWP_V4_ADDR_MASK -> 0x100
            FWP_V4_ADDR_MASK = 256,

            /// FWP_V6_ADDR_MASK -> 0x101
            FWP_V6_ADDR_MASK = 257,

            /// FWP_RANGE_TYPE -> 0x102
            FWP_RANGE_TYPE = 258,

            /// FWP_DATA_TYPE_MAX -> 0x103
            FWP_DATA_TYPE_MAX = 259,
        }

        public enum FWP_MATCH_TYPE : int {
            FWP_MATCH_EQUAL = 0,
            FWP_MATCH_GREATER = 1,
            FWP_MATCH_LESS = 2,
            FWP_MATCH_GREATER_OR_EQUAL = 3,
            FWP_MATCH_LESS_OR_EQUAL = 4,
            FWP_MATCH_RANGE = 5,
            FWP_MATCH_FLAGS_ALL_SET = 6,
            FWP_MATCH_FLAGS_ANY_SET = 7,
            FWP_MATCH_FLAGS_NONE_SET = 8,
            FWP_MATCH_EQUAL_CASE_INSENSITIVE = 9,
            FWP_MATCH_NOT_EQUAL = 10,
            FWP_MATCH_TYPE_MAX = 11,
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_ACTION0 {
            public FirewallActionType type;
            public FWPM_ACTION0_UNION action;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct FWP_VALUE0_UNION {
            [FieldOffset(0)]
            public byte uint8;
            [FieldOffset(0)]
            public ushort uint16;
            [FieldOffset(0)]
            public uint uint32;
            [FieldOffset(0)]
            public IntPtr uint64; // UINT64*
            [FieldOffset(0)]
            public sbyte int8;
            [FieldOffset(0)]
            public short int16;
            [FieldOffset(0)]
            public int int32;
            [FieldOffset(0)]
            public IntPtr int64; // INT64* 
            [FieldOffset(0)]
            public float float32;
            [FieldOffset(0)]
            public IntPtr double64; // double* 
            [FieldOffset(0)]
            public IntPtr byteArray16; // FWP_BYTE_ARRAY16* 
            [FieldOffset(0)]
            public IntPtr byteBlob; // FWP_BYTE_BLOB*
            [FieldOffset(0)]
            public IntPtr sid; // SID* 
            [FieldOffset(0)]
            public IntPtr sd; // FWP_BYTE_BLOB* 
            [FieldOffset(0)]
            public IntPtr tokenInformation; // FWP_TOKEN_INFORMATION* 
            [FieldOffset(0)]
            public IntPtr tokenAccessInformation; // FWP_BYTE_BLOB* 
            [FieldOffset(0)]
            public IntPtr unicodeString; // LPWSTR 
            [FieldOffset(0)]
            public IntPtr byteArray6; // FWP_BYTE_ARRAY6* 
            [FieldOffset(0)]
            public IntPtr bitmapArray64; // FWP_BITMAP_ARRAY64*
            [FieldOffset(0)]
            public IntPtr v4AddrMask; // FWP_V4_ADDR_AND_MASK* 
            [FieldOffset(0)]
            public IntPtr v6AddrMask; // FWP_V6_ADDR_AND_MASK* 
            [FieldOffset(0)]
            public IntPtr rangeValue; // FWP_RANGE0* 
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FWP_VALUE0 {
            public FirewallDataType type;
            public FWP_VALUE0_UNION value;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FWP_BYTE_BLOB {
            public int size;
            /* [unique][size_is] */
            public IntPtr data;

            public byte[] ToArray() {
                if (size <= 0 || data == IntPtr.Zero) {
                    return new byte[0];
                }
                byte[] ret = new byte[size];
                Marshal.Copy(data, ret, 0, ret.Length);
                return ret;
            }

            public Guid ToGuid() {
                var bytes = ToArray();
                if (bytes.Length != 16)
                    return Guid.Empty;
                return new Guid(bytes);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct FWPM_DISPLAY_DATA0 {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string name;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string description;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct FWPM_PROVIDER0 {
            public Guid providerKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public FirewallProviderFlags flags;
            public FWP_BYTE_BLOB providerData;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string serviceName;
        }

        // https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/280826ad554f33e5e799d9b860a68c2b7becbc06/NtApiDotNet/Net/Firewall/FirewallLayerGuids.cs#L22
        public static class FirewallLayerGuids {
            public static Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = new Guid(0xe1cd9fe7, 0xf4b5, 0x4273, 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50);
            public static Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD = new Guid(0x9eeaa99b, 0xbd22, 0x4227, 0x91, 0x9f, 0x00, 0x73, 0xc6, 0x33, 0x57, 0xb1);
            public static Guid FWPM_CONDITION_IP_LOCAL_PORT = new Guid(0x0c1ba1af, 0x5765, 0x453f, 0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b);
        }

        [Flags]
        public enum FirewallProviderFlags {
            None = 0,
            Persistent = 0x00000001,
            Disabled = 0x00000010
        }

        public enum FirewallDataType {
            Empty = 0,
            UInt8 = Empty + 1,
            UInt16 = UInt8 + 1,
            UInt32 = UInt16 + 1,
            UInt64 = UInt32 + 1,
            Int8 = UInt64 + 1,
            Int16 = Int8 + 1,
            Int32 = Int16 + 1,
            Int64 = Int32 + 1,
            Float = Int64 + 1,
            Double = Float + 1,
            ByteArray16 = Double + 1,
            ByteBlob = ByteArray16 + 1,
            Sid = ByteBlob + 1,
            SecurityDescriptor = Sid + 1,
            TokenInformation = SecurityDescriptor + 1,
            TokenAccessInformation = TokenInformation + 1,
            UnicodeString = TokenAccessInformation + 1,
            ByteArray6 = UnicodeString + 1,
            BitmapIndex = ByteArray6 + 1,
            BitmapArray64 = BitmapIndex + 1,
            SingleDataTypeMax = 0xff,
            V4AddrMask = SingleDataTypeMax + 1,
            V6AddrMask = V4AddrMask + 1,
            Range = V6AddrMask + 1
        }
        public enum FirewallActionType : uint {
            Terminating = 0x00001000,
            Block = 0x00000001 | Terminating,
            Permit = 0x00000002 | Terminating,
            CalloutTerminating = 0x00000003 | Callout | Terminating,
            CalloutInspection = 0x00000004 | Callout | NonTerminating,
            CalloutUnknown = 0x00000005 | Callout,
            Continue = 0x00000006 | NonTerminating,
            None = 0x00000007,
            NoneNoMatch = 0x00000008,
            BitmapIndexSet = 0x00000009,
            NonTerminating = 0x00002000,
            Callout = 0x00004000,
            All = 0xFFFFFFFF
        }

        [Flags]
        public enum FirewallFilterFlags {
            None = 0x00000000,
            Persistent = 0x00000001,
            Boottime = 0x00000002,
            HasProviderContext = 0x00000004,
            ClearActionRight = 0x00000008,
            PermitIfCalloutUnregistered = 0x00000010,
            Disabled = 0x00000020,
            Indexed = 0x00000040,
            HasSecurityRealmProviderContext = 0x00000080,
            SystemOSOnly = 0x00000100,
            GameOSOnly = 0x00000200,
            SilentMode = 0x00000400,
            IPSecNoAcquireInitiate = 0x00000800,
        }

        public enum NetFwProfileType2 {
            Domain = 0x00000001,
            Private = 0x00000002,
            Public = 0x00000004,
            All = 0x7FFFFFFF
        }

        [Guid("8267BBE3-F890-491C-B7B6-2DB1EF0E5D2B")]
        [ComImport]
        public interface INetFwServiceRestriction {
            [DispId(1)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            // ReSharper disable once TooManyArguments
            void RestrictService(
                [MarshalAs(UnmanagedType.BStr)][In] string serviceName,
                [MarshalAs(UnmanagedType.BStr)][In] string appName,
                [In] bool restrictService,
                [In] bool serviceSIDRestricted
            );

            [DispId(2)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            bool ServiceRestricted(
                [MarshalAs(UnmanagedType.BStr)][In] string serviceName,
                [MarshalAs(UnmanagedType.BStr)][In] string appName
            );

            [DispId(3)]
            INetFwRules Rules {
                [DispId(3)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.Interface)]
                get;
            }
        }

        [DllImport("ole32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        public static extern uint CoInitializeEx([In, Optional] IntPtr pvReserved, [In] COINIT dwCoInit); //DWORD

        public enum COINIT : uint
        {
            COINIT_MULTITHREADED = 0x0,
            COINIT_APARTMENTTHREADED = 0x2,
            COINIT_DISABLE_OLE1DDE = 0x4,
            COINIT_SPEED_OVER_MEMORY = 0x8,
        }

        [DllImport("ole32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint CoCreateInstance(Guid rclsid, IntPtr pUnkOuter, CLSCTX dwClsContext, Guid riid, out IntPtr ppv);

        [Flags]
        public enum CLSCTX : uint {
            INPROC_SERVER = 0x1,
            INPROC_HANDLER = 0x2,
            LOCAL_SERVER = 0x4,
            INPROC_SERVER16 = 0x8,
            REMOTE_SERVER = 0x10,
            INPROC_HANDLER16 = 0x20,
            RESERVED1 = 0x40,
            RESERVED2 = 0x80,
            RESERVED3 = 0x100,
            RESERVED4 = 0x200,
            NO_CODE_DOWNLOAD = 0x400,
            RESERVED5 = 0x800,
            NO_CUSTOM_MARSHAL = 0x1000,
            ENABLE_CODE_DOWNLOAD = 0x2000,
            NO_FAILURE_LOG = 0x4000,
            DISABLE_AAA = 0x8000,
            ENABLE_AAA = 0x10000,
            FROM_DEFAULT_CONTEXT = 0x20000,
            INPROC = INPROC_SERVER | INPROC_HANDLER,
            SERVER = INPROC_SERVER | LOCAL_SERVER | REMOTE_SERVER,
            ALL = SERVER | INPROC_HANDLER
        }

        [Guid("98325047-C671-4174-8D81-DEFCD3F03186")]
        [ComImport]
        public interface INetFwPolicy2 {
            [DispId(1)]
            int CurrentProfileTypes {
                [DispId(1)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                get;
            }

            [DispId(2)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            bool get_FirewallEnabled([In] NetFwProfileType2 profileType);

            [DispId(2)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            void set_FirewallEnabled([In] NetFwProfileType2 profileType, [In] bool enabled);

            [DispId(3)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            object get_ExcludedInterfaces([In] NetFwProfileType2 profileType);

            [DispId(3)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            void set_ExcludedInterfaces(
                [In] NetFwProfileType2 profileType,
                [In] object interfaces);

            [DispId(4)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            bool get_BlockAllInboundTraffic([In] NetFwProfileType2 profileType);

            [DispId(4)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            void set_BlockAllInboundTraffic([In] NetFwProfileType2 profileType, [In] bool block);

            [DispId(5)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            bool get_NotificationsDisabled([In] NetFwProfileType2 profileType);

            [DispId(5)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            void set_NotificationsDisabled([In] NetFwProfileType2 profileType, [In] bool disabled);

            [DispId(6)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            bool get_UnicastResponsesToMulticastBroadcastDisabled([In] NetFwProfileType2 profileType);

            [DispId(6)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            void set_UnicastResponsesToMulticastBroadcastDisabled(
                [In] NetFwProfileType2 profileType,
                [In] bool disabled
            );

            [DispId(7)]
            INetFwRules Rules {
                [DispId(7)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.Interface)]
                get;
            }

            [DispId(8)]
            INetFwServiceRestriction ServiceRestriction {
                [DispId(8)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.Interface)]
                get;
            }

            [DispId(9)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            void EnableRuleGroup(
                [In] int profileTypesBitmask,
                [MarshalAs(UnmanagedType.BStr)][In] string group,
                [In] bool enable
            );

            [DispId(10)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            bool IsRuleGroupEnabled([In] int profileTypesBitmask, [MarshalAs(UnmanagedType.BStr)][In] string group);

            [DispId(11)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            void RestoreLocalFirewallDefaults();

            [DispId(12)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            NetFwAction get_DefaultInboundAction([In] NetFwProfileType2 profileType);

            [DispId(12)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            void set_DefaultInboundAction([In] NetFwProfileType2 profileType, [In] NetFwAction action);

            [DispId(13)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            NetFwAction get_DefaultOutboundAction([In] NetFwProfileType2 profileType);

            [DispId(13)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            void set_DefaultOutboundAction([In] NetFwProfileType2 profileType, [In] NetFwAction action);

            [DispId(14)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            bool get_IsRuleGroupCurrentlyEnabled([MarshalAs(UnmanagedType.BStr)][In] string group);

            [DispId(15)]
            NetFwModifyState LocalPolicyModifyState {
                [DispId(15)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                get;
            }
        }
        public enum NetFwModifyState {
            Ok,
            GroupPolicyOverride,
            InboundBlocked
        }

        public enum NetFwAction {
            Block,
            Allow
        }

        [Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
        [ComImport]
        public interface INetFwRule {
            [DispId(1)]
            string Name {
                [DispId(1)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(1)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(2)]
            string Description {
                [DispId(2)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(2)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(3)]
            string ApplicationName {
                [DispId(3)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(3)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(4)]
            string serviceName {
                [DispId(4)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(4)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(5)]
            int Protocol {
                [DispId(5)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                get;
                [DispId(5)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: In]
                set;
            }

            [DispId(6)]
            string LocalPorts {
                [DispId(6)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(6)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(7)]
            string RemotePorts {
                [DispId(7)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(7)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(8)]
            string LocalAddresses {
                [DispId(8)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(8)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(9)]
            string RemoteAddresses {
                [DispId(9)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(9)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(10)]
            string IcmpTypesAndCodes {
                [DispId(10)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(10)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(11)]
            NetFwRuleDirection Direction {
                [DispId(11)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                get;
                [DispId(11)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: In]
                set;
            }

            [DispId(12)]
            object Interfaces {
                [DispId(12)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                get;
                [DispId(12)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: In]
                set;
            }

            [DispId(13)]
            string InterfaceTypes {
                [DispId(13)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(13)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(14)]
            bool Enabled {
                [DispId(14)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                get;
                [DispId(14)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: In]
                set;
            }

            [DispId(15)]
            string Grouping {
                [DispId(15)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [return: MarshalAs(UnmanagedType.BStr)]
                get;
                [DispId(15)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: MarshalAs(UnmanagedType.BStr)]
                [param: In]
                set;
            }

            [DispId(16)]
            int Profiles {
                [DispId(16)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                get;
                [DispId(16)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: In]
                set;
            }

            [DispId(17)]
            bool EdgeTraversal {
                [DispId(17)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                get;
                [DispId(17)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: In]
                set;
            }

            [DispId(18)]
            NetFwAction Action {
                [DispId(18)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                get;
                [DispId(18)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                [param: In]
                set;
            }
        }
        public enum NetFwRuleDirection {
            Inbound = 1,
            Outbound = 2
        }

        [Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
        [ComImport]
        public interface INetFwRules : System.Collections.IEnumerable {
            [DispId(1)]
            int Count {
                [DispId(1)]
                [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
                get;
            }

            [DispId(2)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            // ReSharper disable once MethodNameNotMeaningful
            void Add(
                [MarshalAs(UnmanagedType.Interface)] [In]
            INetFwRule rule
            );

            [DispId(3)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            void Remove([MarshalAs(UnmanagedType.BStr)][In] string name);

            [DispId(4)]
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime)]
            [return: MarshalAs(UnmanagedType.Interface)]
            INetFwRule Item([MarshalAs(UnmanagedType.BStr)][In] string name);

            [DispId(-4)]
            IEnumVARIANT GetEnumeratorVariant();
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegOpenKeyEx(IntPtr keyBase,
                string keyName, IntPtr reserved, int access,
                out IntPtr keyHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegEnumKey(IntPtr keyBase, int index, StringBuilder nameBuffer, int bufferLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegQueryValueEx(IntPtr keyBase,
                string valueName, IntPtr reserved, ref RegistryValueKind type,
                IntPtr data, ref int dataSize);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegCloseKey(IntPtr keyHandle);

        [ComVisible(true)]
        public enum RegistryValueKind {
            Unknown,
            String,
            ExpandString,
            Binary,
            DWord,
            MultiString = 7,
            QWord = 11,
        }

        [DllImport("kernel32.dll")]
        public static extern int OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class STARTUPINFO {
            public int cb = Marshal.SizeOf(typeof(STARTUPINFO));
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        public static class ProcessCreationFlags {
            public const uint DEBUG_PROCESS = 0x00000001;
            public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
            public const uint CREATE_SUSPENDED = 0x00000004;
            public const uint DETACHED_PROCESS = 0x00000008;
            public const uint CREATE_NEW_CONSOLE = 0x00000010;
            public const uint NORMAL_PRIORITY_CLASS = 0x00000020;
            public const uint IDLE_PRIORITY_CLASS = 0x00000040;
            public const uint HIGH_PRIORITY_CLASS = 0x00000080;
            public const uint REALTIME_PRIORITY_CLASS = 0x00000100;
            public const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
            public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            public const uint CREATE_SEPARATE_WOW_VDM = 0x00000800;
            public const uint CREATE_SHARED_WOW_VDM = 0x00001000;
            public const uint CREATE_FORCEDOS = 0x00002000;
            public const uint BELOW_NORMAL_PRIORITY_CLASS = 0x00004000;
            public const uint ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000;
            public const uint INHERIT_PARENT_AFFINITY = 0x00010000;
            public const uint INHERIT_CALLER_PRIORITY = 0x00020000;
            public const uint CREATE_PROTECTED_PROCESS = 0x00040000;
            public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            public const uint PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000;
            public const uint PROCESS_MODE_BACKGROUND_END = 0x00200000;
            public const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
            public const uint CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000;
            public const uint CREATE_DEFAULT_ERROR_MODE = 0x04000000;
            public const uint CREATE_NO_WINDOW = 0x08000000;
            public const uint PROFILE_USER = 0x10000000;
            public const uint PROFILE_KERNEL = 0x20000000;
            public const uint PROFILE_SERVER = 0x40000000;
            public const uint CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetUserAdd(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            UInt32 level,
            ref USER_INFO_1 userinfo,
            out UInt32 parm_err
        );

        [DllImport("NetApi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static int NetUserDel(string servername, string username);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetLocalGroupAddMembers(
            string servername,
            string groupname,
            UInt32 level,
            ref LOCALGROUP_MEMBERS_INFO_3 members,
            UInt32 totalentries
        );

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetUserEnum(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            int level,
            int filter,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            out int resume_handle
        );

        [DllImport("netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr buffer);

        // Constants for NetUserEnum function
        public const int FILTER_NORMAL_ACCOUNT = 0x0002;
        public const int NERR_Success = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct USER_INFO_0 {
            public String name;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct USER_INFO_1 {
            [MarshalAs(UnmanagedType.LPWStr)] public string sUsername;
            [MarshalAs(UnmanagedType.LPWStr)] public string sPassword;
            public uint uiPasswordAge;
            public uint uiPriv;
            [MarshalAs(UnmanagedType.LPWStr)] public string sHome_Dir;
            [MarshalAs(UnmanagedType.LPWStr)] public string sComment;
            public uint uiFlags;
            [MarshalAs(UnmanagedType.LPWStr)] public string sScript_Path;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct USER_INFO_23 {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string name;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string fullName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string comment;
            public uint flags;
            public uint sid;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_MEMBERS_INFO_3 {
            public IntPtr lgrmi3_domainandname;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_MEMBERS_INFO_0 {
            public uint lgrmi0_sid;
        }

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool DeleteProfileW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpszSidString,
            [MarshalAs(UnmanagedType.LPWStr)] string lpszProfilePath,
            [MarshalAs(UnmanagedType.LPWStr)] string lpszComputerName
        );

        [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int CreateProfile(
            [MarshalAs(UnmanagedType.LPWStr)] string pszUserSid,
            [MarshalAs(UnmanagedType.LPWStr)] string pszUserName,
            [Out][MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszProfilePath,
            uint cchProfilePath
        );
    }
}
