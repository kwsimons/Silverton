using Silverton.Core.Interop;
using Silverton.Core.Log;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Silverton.Core.Interop.NativeBridge;

namespace Silverton.Injector {

    // Responsible for injecting an in-memory PE into the running process by emulating the native library loader
    // This involves updating the PEB, LDRP internals, invoking TLS callbacks + DllMain, etc
    public class InjectedPE {

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate bool DllMainDelegate(IntPtr hModule, UInt32 ul_reason_for_call, IntPtr lpReserved);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate void TlsCallbackDelegate(IntPtr hModule, UInt32 ul_reason_for_call, IntPtr lpReserved);

        private string absoluteFilePath;
        private InMemoryPE inMemoryPE;
        private bool isMainExecutable;
        private NativeFunctionInvoker functionInvoker;

        // Inject the given PE into the PEB, LDRP internals, invoke TLS callbacks + DllMain
        public static InjectedPE Inject(InMemoryPE inMemoryPE, string absoluteFilePath, NativeFunctionInvoker functionInvoker, bool isMainExecutable = false) {
            return new InjectedPE(inMemoryPE, absoluteFilePath, functionInvoker, isMainExecutable);
        }

        private InjectedPE(InMemoryPE inMemoryPE, string absoluteFilePath, NativeFunctionInvoker functionInvoker, bool isMainExecutable) {
            if (string.IsNullOrEmpty(absoluteFilePath)) throw new ArgumentNullException("File path must be non-empty");
            if (!Path.IsPathRooted(absoluteFilePath)) throw new Exception($"File path is not absolute: {absoluteFilePath}");

            this.absoluteFilePath = absoluteFilePath;
            this.inMemoryPE = inMemoryPE;
            this.functionInvoker = functionInvoker;
            this.isMainExecutable = isMainExecutable;

            this.UpdatePEB(absoluteFilePath);
        }

        public string AbsoluteFilePath {
            get { return this.absoluteFilePath; }
        }

        public InMemoryPE InMemoryPE { 
            get { return inMemoryPE; }
        }

        // Invoke TlsCallback(DLL_PROCESS_ATTACH) on the injected PE
        private void InvokeTlsCallbacksProcessAttach() {
            InvokeTlsCallbacks(NativeBridge.DLL_PROCESS_ATTACH, 0);
        }

        // Invoke TlsCallback(DLL_PROCESS_ATTACH) on the injected PE
        private void InvokeTlsCallbacksProcessDetach() {
            InvokeTlsCallbacks(NativeBridge.DLL_PROCESS_DETACH, 0);
        }

        // Invoke all the TLS callbacks for an injected PE
        private void InvokeTlsCallbacks(UInt32 fdwReason, Int32 lpvReserved) {

            List<IntPtr> tlsFunctionAddresses = inMemoryPE.GetTlsFunctionAddresses();

            functionInvoker.Invoke(() => {
                foreach (var functionAddress in tlsFunctionAddresses) {
                    Logger.Log($"Invoking TLS Callback (VirtualAddress: 0x{functionAddress.ToInt64() - inMemoryPE.BaseAddress.ToInt64():X} AbsoluteAddress: 0x{functionAddress:X}) (hModule: 0x{inMemoryPE.BaseAddress:X} fdwReason: {fdwReason} lpvReserved: 0x{lpvReserved:X})", Logger.LogLevel.INFO);
                    var tlsCallbackFn = Marshal.GetDelegateForFunctionPointer<TlsCallbackDelegate>(functionAddress);
                    tlsCallbackFn(inMemoryPE.BaseAddress, fdwReason, new IntPtr(lpvReserved));
                }
            });
        }

        // Invoke DllMain(DLL_PROCESS_ATTACH) on the injected PE
        private void InvokeDllMainProcessAttach() {
            InvokeDllMainFunction(NativeBridge.DLL_PROCESS_ATTACH, 0);
        }

        // Invoke DllMain(DLL_PROCESS_DETACH) on the injected PE
        private void InvokeDllMainProcessDetach() {
            InvokeDllMainFunction(NativeBridge.DLL_PROCESS_DETACH, 0);
        }

        // Invoke DllMain on the injected PE
        private void InvokeDllMainFunction(UInt32 fdwReason, Int32 lpvReserved) {

            if (inMemoryPE.isExecutable()) {
                Logger.Log("Is an EXE, skipping DLLMain() invocation", Logger.LogLevel.TRACE);
                return;
            }

            if (!inMemoryPE.HasEntryPoint) {
                Logger.Log("Is a DLL, but does not have an entry point defined, skipping DLLMain() invocation", Logger.LogLevel.TRACE);
                return;
            }

            functionInvoker.Invoke(() => {
                IntPtr functionAddress = this.inMemoryPE.EntryPointAddress;
                Logger.Log($"Invoking DllMain (VirtualAddress: 0x{functionAddress.ToInt64() - inMemoryPE.BaseAddress.ToInt64():X} AbsoluteAddress: 0x{functionAddress:X}) (hModule: 0x{inMemoryPE.BaseAddress:X} fdwReason: {fdwReason} lpvReserved: 0x{lpvReserved:X})", Logger.LogLevel.INFO);
                
                var dllMainFn = Marshal.GetDelegateForFunctionPointer<DllMainDelegate>(functionAddress);
                bool result = dllMainFn(inMemoryPE.BaseAddress, fdwReason, new IntPtr(lpvReserved));
                if (!result) {
                    Logger.Log($"DllMain method indicated it was not successfully (hModule: 0x{inMemoryPE.BaseAddress:X} fdwReason: {fdwReason} lpvReserved: 0x{lpvReserved:X})", Logger.LogLevel.WARN);
                }
            });
        }

        // Create a LDR_DATA_TABLE_ENTRY and insert it into the PEB, emulating the native loader wherever possible
        [MethodImpl(MethodImplOptions.Synchronized)]
        private void UpdatePEB(string fullFilePath) {

            // Lock the loader
            ulong lockState = 0;
            ulong lockCookie = 0;
            int result = 0;
            do {
                result = NativeBridge.LdrLockLoaderLock(0x02, ref lockState, ref lockCookie);
            }
            while (result != 0 || lockState != 0x01);

            try {

                IntPtr pebAddress = GetPEBAddress(Process.GetCurrentProcess().Handle);

                PEB peb = (PEB)Marshal.PtrToStructure(pebAddress, typeof(PEB));
                PEB_LDR_DATA ldr = (PEB_LDR_DATA)Marshal.PtrToStructure(peb.Ldr, typeof(PEB_LDR_DATA));

                // Allocate memory
                var newEntryAddress = Marshal.AllocHGlobal(Marshal.SizeOf<LDR_DATA_TABLE_ENTRY>()); // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
                Logger.Log($"Allocated 0x{newEntryAddress:X} for LDR_DATA_TABLE_ENTRY", Logger.LogLevel.TRACE);

                ulong Flags = 0;
                if (this.inMemoryPE.isDll()) {
                    Flags |= 0x00000004; // ImageDll
                    Flags |= 0x00080000; // ProcessAttachCalled
                }
                if (this.inMemoryPE.isExecutable()) {
                    Flags |= 0x00040000; // DontCallForThreads
                }
                Flags |= 0x00004000; //  LDRP_ENTRY_PROCESSED

                var parent = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(ldr.InLoadOrderLinks.Flink, typeof(LDR_DATA_TABLE_ENTRY));
                var dllFlags = NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_IMAGE_DLL |
                    NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_PROTECT_DELAY_LOAD |
                    NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_LOAD_NOTIFICATIONS_SENT |
                    NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_ENTRY_PROCESSED |
                    NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_IN_LEGACY_LISTS |
                    NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_PROCESS_ATTACH_CALLED; // LDRP_PROCESS_ATTACH_CALLED dictates whether DLL_THREAD_ATTACH is automatically called

                var exeFlags = NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_IMAGE_DLL |
                    NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_PROTECT_DELAY_LOAD |
                    NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_LOAD_NOTIFICATIONS_SENT |
                    NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_ENTRY_PROCESSED |
                    NativeBridge.LDR_DATA_TABLE_ENTRY_FLAGS.LDRP_IN_LEGACY_LISTS;

                // Create the new entry
                var newEntry = new LDR_DATA_TABLE_ENTRY {
                    FullDllName = new UNICODE_STRING(fullFilePath),
                    BaseDllName = new UNICODE_STRING(this.inMemoryPE.FileName),
                    SizeOfImage = this.inMemoryPE.SizeOfImage,
                    DllBase = this.inMemoryPE.BaseAddress,
                    EntryPoint = this.inMemoryPE.EntryPointAddress,
                    InLoadOrderLinks = new LIST_ENTRY {
                        Blink = IntPtr.Zero,
                        Flink = IntPtr.Zero,
                    },
                    InMemoryOrderLinks = new LIST_ENTRY {
                        Blink = IntPtr.Zero,
                        Flink = IntPtr.Zero,
                    },
                    InInitializationOrderLinks = new LIST_ENTRY {
                        Blink = IntPtr.Zero,
                        Flink = IntPtr.Zero,
                    },
                    ObsoleteLoadCount = 0x1,
                    Flags = (uint)(this.inMemoryPE.isDll() ? dllFlags : exeFlags),
                    TlsIndex = 0x0,
                    HashLinks = new LIST_ENTRY {
                        Blink = IntPtr.Zero,
                        Flink = IntPtr.Zero,
                    },
                    OriginalBase = (ulong)this.inMemoryPE.BaseAddress.ToInt64(),
                    LoadReason = LDR_DLL_LOAD_REASON.DynamicLoad,
                    ReferenceCount = 0x1,
                    ImplicitPathOptions = 0x8,
                    CheckSum = inMemoryPE.CheckSum,
                    NodeModuleLink = new LIST_ENTRY {
                        Blink = IntPtr.Zero,
                        Flink = IntPtr.Zero,
                    },
                    Lock = new IntPtr(0x0),
                    BaseAddressIndexNode = new RTL_BALANCED_NODE {
                        Left = IntPtr.Zero,
                        Right = IntPtr.Zero,
                        ParentValue = 0x0,
                    },

                    // TODO
                    //MappingInfoIndexNode = parent.MappingInfoIndexNode,
                    //SwitchBackContext = parent.SwitchBackContext,
                    LoadTime = parent.LoadTime, // TODO: pNtQuerySystemTime
                    TimeDateStamp = parent.TimeDateStamp, // TODO: pNtHeaders->FileHeader.TimeDateStam
                };

                // Figure out the DDAG
                {
                    var pDdagNode = Marshal.AllocHGlobal(Marshal.SizeOf<LDR_DDAG_NODE>());
                    newEntry.DdagNode = pDdagNode;

                    var pNodeModuleLink = newEntryAddress + 0xA0;
                    var ddagNode = new LDR_DDAG_NODE {
                        State = LDR_DDAG_STATE.LdrModulesReadyToRun,
                        LoadCount = 1,
                        Modules = new LIST_ENTRY {
                            Blink = pNodeModuleLink,
                            Flink = pNodeModuleLink,
                        }
                    };
                    newEntry.NodeModuleLink.Flink = newEntry.NodeModuleLink.Blink = pDdagNode + 0x0;
                    Marshal.StructureToPtr(ddagNode, pDdagNode, false);

                    Logger.Log($"Added LDR_DDAG_NODE at 0x{pDdagNode:X} to the entry", Logger.LogLevel.TRACE);
                }

                // Insert into the exception handlers table
                {
                    var ntStatus = RtlInsertInvertedFunctionTable(newEntry.DllBase, inMemoryPE.SizeOfImage);
                    if (ntStatus != 0) {
                        //throw new Exception($"Error inserting into inverted function table: 0x{GetLastError():X}");
                        Logger.Log($"Error inserting into inverted function table: 0x{ntStatus:X} (Error: 0x{GetLastError():X})", Logger.LogLevel.ERROR);
                    }
                    else {
                        Logger.Log($"Inserted into the exception handler table: 0x{ntStatus:X} (Error: 0x{GetLastError():X})", Logger.LogLevel.DEBUG);
                    }
                }

                // Insert the BaseAddressIndexNode into the RLB tree
                {
                    RTL_RB_TREE tree = GetLdrpModuleBaseAddressIndex();
                    bool insertIntoRight = false;

                    IntPtr nodeAddr = tree.Root;
                    while (true) {
                        IntPtr address = nodeAddr - 0xC8; // BaseAddressIndexNode
                        var entry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(address, typeof(LDR_DATA_TABLE_ENTRY));

                        // Goes to the left
                        if (inMemoryPE.BaseAddress.ToInt64() < entry.DllBase.ToInt64()) {
                            // Nothing to the left, we will place it here
                            if (entry.BaseAddressIndexNode.Left == IntPtr.Zero) {
                                break;
                            }
                            // Otherwise, navigate to the left
                            nodeAddr = entry.BaseAddressIndexNode.Left;

                            // Goes to the right
                        }
                        else if (inMemoryPE.BaseAddress.ToInt64() > entry.DllBase.ToInt64()) {
                            // Nothing to the right, we will place it here
                            if (entry.BaseAddressIndexNode.Right == IntPtr.Zero) {
                                insertIntoRight = true;
                                break;
                            }
                            // Otherwise, navigate to the right
                            nodeAddr = entry.BaseAddressIndexNode.Right;

                        }
                        else {
                            throw new Exception($"Same DLL loaded twice, this shouldn't happen. (BaseDllName: {entry.BaseDllName}, DllBase: 0x{entry.DllBase})");
                        }
                    }

                    // Update the parent of our RB Tree
                    newEntry.BaseAddressIndexNode.ParentValue = (ulong)nodeAddr.ToInt64();

                    IntPtr baseAddressIndexNodeAddress = newEntryAddress + 0xC8; // BaseAddressIndexNode
                    RtlRbInsertNodeEx(GetLdrpModuleBaseAddressIndexAddress(), nodeAddr, insertIntoRight, baseAddressIndexNodeAddress);

                    Logger.Log($"Inserted node 0x{baseAddressIndexNodeAddress:X} into ModuleBaseAddress RBTree {(insertIntoRight ? "right" : "left")} of parent 0x{nodeAddr:X}", Logger.LogLevel.TRACE);
                }

                // Calculate hash
                {
                    ulong hash = 0;
                    RtlHashUnicodeString(ref newEntry.BaseDllName, true, 0, ref hash);
                    newEntry.BaseNameHashValue = hash;
                }

                // Insert into the LDRP hash table at the tail
                {
                    // Setup our hash link to point to itself
                    var pHashLinks = IntPtr.Add(newEntryAddress, Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("HashLinks").ToInt32());

                    IntPtr pHashTable = FindLdrpHashTable();
                    ulong hashTableKey = NativeBridge.CreateCacheKey(newEntry.BaseDllName);

                    var pHashTableHead = IntPtr.Add(pHashTable, (int)hashTableKey * Marshal.SizeOf<LIST_ENTRY>());
                    var HashTableHead = (LIST_ENTRY)Marshal.PtrToStructure(pHashTableHead, typeof(LIST_ENTRY));
                    var headEntry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(IntPtr.Subtract(HashTableHead.Flink, Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("HashLinks").ToInt32()), typeof(LDR_DATA_TABLE_ENTRY));
                    Logger.Log($"HEAD (flink: 0x{HashTableHead.Flink:X}, blink: 0x{HashTableHead.Blink:X}, dll: {headEntry.BaseDllName})", Logger.LogLevel.TRACE);

                    var pHashTableTail = HashTableHead.Blink;
                    newEntry.HashLinks.Flink = pHashTableHead;
                    newEntry.HashLinks.Blink = pHashTableTail;

                    HashTableHead.Blink = pHashLinks;
                    Marshal.StructureToPtr(HashTableHead, pHashTableHead, false);

                    var HashTableTail = (LIST_ENTRY)Marshal.PtrToStructure(pHashTableTail, typeof(LIST_ENTRY));
                    var tailEntry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(IntPtr.Subtract(pHashTableTail, Marshal.OffsetOf<LDR_DATA_TABLE_ENTRY>("HashLinks").ToInt32()), typeof(LDR_DATA_TABLE_ENTRY));
                    Logger.Log($"TAIL (flink: 0x{HashTableTail.Flink:X}, blink: 0x{HashTableTail.Blink:X}, dll: {tailEntry.BaseDllName})", Logger.LogLevel.TRACE);
                    HashTableTail.Flink = pHashLinks;
                    Marshal.StructureToPtr(HashTableTail, pHashTableTail, false);

                    Logger.Log($"Added hash link 0x{pHashLinks:X} to the hash table at position 0x{hashTableKey:X} (head: 0x{pHashTableHead:X}, tail: 0x{pHashTableTail:X})", Logger.LogLevel.TRACE);
                }

                // Add to the tail of InLoadOrderLinks
                {
                    var pEntry = newEntryAddress + 0x00;
                    var pHead = peb.Ldr + 0x10;
                    var pTail = ldr.InLoadOrderLinks.Blink;

                    newEntry.InLoadOrderLinks.Flink = pHead;
                    newEntry.InLoadOrderLinks.Blink = pTail;

                    var Head = (LIST_ENTRY)Marshal.PtrToStructure(pHead, typeof(LIST_ENTRY));
                    Head.Blink = pEntry;
                    Marshal.StructureToPtr(Head, pHead, false);

                    var Tail = (LIST_ENTRY)Marshal.PtrToStructure(pTail, typeof(LIST_ENTRY));
                    Tail.Flink = pEntry;
                    Marshal.StructureToPtr(Tail, pTail, false);

                    Logger.Log($"Added InLoadOrderLinks tail 0x{pEntry:X} (head: 0x{pHead:X}, tail: 0x{pTail:X})", Logger.LogLevel.TRACE);
                }

                // Add to the tail of InMemoryOrderLinks
                {
                    var pEntry = newEntryAddress + 0x10;
                    var pHead = peb.Ldr + 0x20; // ldr.InMemoryOrderLinks;
                    var pTail = ldr.InMemoryOrderLinks.Blink;

                    newEntry.InMemoryOrderLinks.Flink = pHead;
                    newEntry.InMemoryOrderLinks.Blink = pTail;

                    var Head = (LIST_ENTRY)Marshal.PtrToStructure(pHead, typeof(LIST_ENTRY));
                    Head.Blink = pEntry;
                    Marshal.StructureToPtr(Head, pHead, false);

                    var Tail = (LIST_ENTRY)Marshal.PtrToStructure(pTail, typeof(LIST_ENTRY));
                    Tail.Flink = pEntry;
                    Marshal.StructureToPtr(Tail, pTail, false);

                    Logger.Log($"Added InMemoryOrderLinks tail 0x{pEntry:X} (head: 0x{pHead:X}, tail: 0x{pTail:X})", Logger.LogLevel.TRACE);
                }

                // Add to the tail of InInitializationOrderLinks
                {
                    var pEntry = newEntryAddress + 0x20;
                    var pHead = peb.Ldr + 0x30; // ldr.InInitializationOrderLinks;
                    var pTail = ldr.InInitializationOrderLinks.Blink;

                    newEntry.InInitializationOrderLinks.Flink = pHead;
                    newEntry.InInitializationOrderLinks.Blink = pTail;

                    var Head = (LIST_ENTRY)Marshal.PtrToStructure(pHead, typeof(LIST_ENTRY));
                    Head.Blink = pEntry;
                    Marshal.StructureToPtr(Head, pHead, false);

                    var Tail = (LIST_ENTRY)Marshal.PtrToStructure(pTail, typeof(LIST_ENTRY));
                    Tail.Flink = pEntry;
                    Marshal.StructureToPtr(Tail, pTail, false);

                    Logger.Log($"Added InInitializationOrderLinks tail 0x{pEntry:X} (head: 0x{pHead:X}, tail: 0x{pTail:X})", Logger.LogLevel.TRACE);
                }

                // Add entry to memory slot
                Marshal.StructureToPtr(newEntry, newEntryAddress, false);
                Logger.Log($"Wrote LDR_DATA_TABLE_ENTRY to address 0x{newEntryAddress:X} for dll '{newEntry.BaseDllName}'", Logger.LogLevel.DEBUG);

                // Insert into the Tls Data table
                // NOTE: We must do this AFTER we persist newEntry into memory
                // NOTE: Needed by conhost.exe
                {
                    if (inMemoryPE.OptionalHeader.TLSTable.Size > 0) {

                        // The strategy here is to take the FIRST in-load-order DLL (that gets TLS index = 0) and OVERRIDE it in favor of our injected DLLs TLS
                        // Find the first in load order module, call LdrpReleaseTlsEntry(inLoadOrderFlink) to release it
                        // Then call LdrpHandleTlsData(newEntryAddress) on mine
                        // NOTE: This assumes that the first in load order DLL has a .tls section that we can take over ...

                        // Evict it from index 0
                        if (this.isMainExecutable) {
                            Logger.Log($"Releasing first-slot (static) TLS entry", Logger.LogLevel.DEBUG);

                            if (LdrpReleaseTlsEntry(ldr.InLoadOrderLinks.Flink) != 0) {
                                throw new Exception($"Error handling TLS data, calling LdrpReleaseTlsEntry(): 0x{GetLastError():X}");
                            }
                        }

                        Logger.Log($"dllLibrary.OptionalHeader.TLSTable.Size for {newEntry.BaseDllName.ToString()}  = 0x{inMemoryPE.OptionalHeader.TLSTable.Size:X}", Logger.LogLevel.TRACE);
                        if (LdrpHandleTlsData(newEntryAddress) != 0) {
                            throw new Exception($"Error handling TLS data, calling LdrpHandleTlsData(): 0x{GetLastError():X}");
                        }
                        Logger.Log($"Initialized static TLS data", Logger.LogLevel.DEBUG);

                        // Since this DLL has static TLS, lock it in
                        // Entry->ObsoleteLoadCount = (USHORT)0xffff;
                        // Mark this as having thread local storage
                        // Entry->TlsIndex = (USHORT)0xffff;\
                    }
                }

            } finally {
                // Unlock
                if (NativeBridge.LdrUnlockLoaderLock(0x00, lockCookie) != 0) {
                    throw new Exception("Unable to unlock loader");
                }
            }

            // Call TLS callbacks
            this.InvokeTlsCallbacksProcessAttach();

            // Call PROCESS_ATTACH
            this.InvokeDllMainProcessAttach();

            Logger.Log($"Wrote '{inMemoryPE.FileName}' LDR_DATA_TABLE_ENTRY to the PEB", Logger.LogLevel.TRACE);
        }
    }
}
