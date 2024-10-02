using System;
using System.Runtime.InteropServices;
using Silverton.Core.Interop;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using Silverton.Core.Image;
using Silverton.Core.Log;
using static Silverton.Core.Interop.NativeBridge;
using System.IO;

namespace Silverton.Injector {

    // Responsible for injecting a PE into memory, updating referenced memory addresses and imports where necessary.
    public class InMemoryPE {

        private PEImage pe;
        private string fileName;
        private IntPtr baseAddress;
        private int dwFlags;
        private List<ImportedFunction> importedFunctions = new List<ImportedFunction>();
        private List<ExportedFunction> exportedFunctions = new List<ExportedFunction>();

        // Does not resolve child dlls
        public static InMemoryPE LoadExe(string fullPath, int dwFlags) {
            Logger.Log($"Writing EXE '{fullPath}' to memory", Logger.LogLevel.DEBUG);
            return Load(fullPath, dwFlags);
        }

        // Does resolves child dlls
        public static InMemoryPE LoadDll(string fullPath, int dwFlags, DllLoader dllLoaderDllLoader) {
            Logger.Log($"Writing PE '{fullPath}' to memory", Logger.LogLevel.DEBUG);
            var pe = Load(fullPath, dwFlags);
            pe.Resolve(dllLoaderDllLoader);
            return pe;
        }

        private static InMemoryPE Load(string fullPath, int dwFlags) {
            byte[] bytes = File.ReadAllBytes(fullPath);
            PEImage pe = PEImage.PEReader.ParseHeader(bytes);
            return new InMemoryPE(pe, bytes, Path.GetFileName(fullPath), dwFlags);
        }

        private InMemoryPE(PEImage pe, byte[] bytes, string fileName, int dwFlags) {

            // Punt
            if (pe.Is32Bit) {
                throw new NotSupportedException("Loading 32-bit DLLs is not supported (yet)");
            }

            this.baseAddress = WriteToMemory(pe, bytes, fileName);
            this.fileName = fileName;
            this.pe = pe;
            this.dwFlags = dwFlags;
        }

        public void Resolve(DllLoader dllLoader) {

            // Extract our imported/exported function information
            this.importedFunctions = GetImportedFunctions();
            this.exportedFunctions = GetExportedFunctions(dllLoader);

            // Patch the import table with the actual function addresses
            // TODO: If the dwFlag is DONT_RESOLVE_DLL_REFERENCES don't patch import table
            PatchImportTable(dllLoader);

            // Patch the relocation table based on relative -> absolute addresses
            PatchRelocationTable();

            // Do this after relocation is performed
            UpdateImageBase();

            // Do this last, as it restricts our ability to write
            SetSectionsMemoryPermissions();
        }

        // Where there is an entry point address specific
        public bool HasEntryPoint {
            get {
                return pe.OptionalHeader64.AddressOfEntryPoint != 0;
            }
        }

        // Absolute exe / dll entry point address
        public IntPtr EntryPointAddress {
            get {
                if (HasEntryPoint) {
                    return IntPtr.Add(baseAddress, (int)pe.OptionalHeader64.AddressOfEntryPoint);
                }
                return IntPtr.Zero;
            }
        }

        // PE optional header
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader {
            get { return pe.optionalHeader64; }
        }

        public string FileName {
            get { return fileName; }
        }

        public uint CheckSum {
            get { return pe.optionalHeader64.CheckSum; }
        }

        public uint SizeOfImage {
            get { return pe.OptionalHeader64.SizeOfImage; }
        }

        // Absolute base address of the PE
        public IntPtr BaseAddress {
            get { return baseAddress; }
        }

        public List<ImportedFunction> Imports {
            get { return importedFunctions; }
        }

        public List<ExportedFunction> Exports {
            get { return exportedFunctions; }
        }

        public IntPtr GetExportedFunctionAddress(string functionName) {

            var func = GetExportedFunction(functionName);
            if (!func.HasValue) {
                throw new Exception($"Could not find '{this.fileName}!{functionName}', available functions: {string.Join(",", exportedFunctions.Select((t) => t.FunctionName))}");
            }
            return func.Value.FunctionAddress;
        }

        public IntPtr GetExportedFunctionAddress(ushort ordinal) {

            var func = GetExportedFunction(ordinal);
            if (!func.HasValue) {
                throw new Exception($"Could not find ordinal 0x{ordinal:X} in '{this.fileName}', available ordinals: {string.Join(",", exportedFunctions.Select((t) => t.Ordinal))}");
            }
            return func.Value.FunctionAddress;
        }

        public ExportedFunction? GetExportedFunction(string functionName) {
            foreach (var exportedFunction in exportedFunctions) {
                if (exportedFunction.FunctionName == functionName) {
                    return exportedFunction;
                }
            }
            return null;
        }

        public ExportedFunction? GetExportedFunction(ushort ordinal) {
            foreach (var exportedFunction in exportedFunctions) {
                if (exportedFunction.Ordinal == ordinal) {
                    return exportedFunction;
                }
            }
            return null;
        }

        public bool isExecutable() {
            return
                ((pe.FileHeader.Characteristics & 0x02) != 0) // No unresolved external references
                &&
                ((pe.FileHeader.Characteristics & 0x2000) == 0); // Is not a DLL
        }

        public bool isDll() {
            return !isExecutable();
        }

        // Update the image base address to reflect the actual memory address
        private void UpdateImageBase() {
            // IMAGE_OPTIONAL_HEADER64.ImageBase
            IntPtr relativeOffset = IntPtr.Add(Marshal.OffsetOf<IMAGE_OPTIONAL_HEADER64>("ImageBase"), 4 /* NT header signature */ + (int) this.pe.dosHeader.e_lfanew + Marshal.SizeOf<IMAGE_FILE_HEADER>());
            IntPtr absoluteAddress = IntPtr.Add(baseAddress, relativeOffset.ToInt32());
            Marshal.WriteInt64(absoluteAddress, baseAddress.ToInt64());
            Logger.Log($"Updated PE header image base address to 0x{baseAddress:X}", Logger.LogLevel.TRACE);
        }

        // Write each section of the PE into memory
        private static IntPtr WriteToMemory(PEImage pe, byte[] bytes, string fileName) {

            // Allocate size for the entire PE image in memory
            IntPtr baseAddress = VirtualAlloc(IntPtr.Zero, pe.OptionalHeader64.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
            int errorCode = Marshal.GetLastWin32Error();
            if(baseAddress == IntPtr.Zero) {
                throw new Exception($"Unable to allocate base memory: 0x{errorCode:X}", new Win32Exception(errorCode));
            }

            // Copy the header
            Marshal.Copy(bytes, 0, baseAddress, (int)pe.OptionalHeader64.SizeOfHeaders);
            Logger.Log($"Wrote PE header to memory at address 0x{baseAddress:X}", Logger.LogLevel.TRACE);

            // Copy the sections to their virtual address offsets
            for (var i = 0; i < pe.FileHeader.NumberOfSections; i++) {
                var section = pe.ImageSectionHeaders[i];

                if (section.SizeOfRawData == 0) {
                    Logger.Log($"Skipping section '{new string(section.Name)}' as it has no bytes", Logger.LogLevel.WARN);
                    continue;
                }

                IntPtr writeAddress = IntPtr.Add(baseAddress, (int) section.VirtualAddress);

                var memAddress = VirtualAlloc(writeAddress, section.SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
                errorCode = Marshal.GetLastWin32Error();
                if (memAddress == IntPtr.Zero) {
                    throw new Exception($"Unable to allocate 0x{section.SizeOfRawData:X} bytes of memory for section '{new string(section.Name)}' (ErrorCode: 0x{errorCode:X})", new Win32Exception(errorCode));
                }

                if (section.SizeOfRawData > 0) {
                    Marshal.Copy(bytes, (int)section.PointerToRawData, memAddress, (int)section.SizeOfRawData);
                    Logger.Log($"Wrote PE section {new string(section.Name)} (0x{section.VirtualAddress:X} - 0x{section.VirtualAddress + section.SizeOfRawData:X}) to address 0x{writeAddress:X}", Logger.LogLevel.TRACE);
                }
            }

            Logger.Log($"Wrote '{fileName}' PE into memory at 0x{baseAddress:X}");
            return baseAddress;
        }

        // Sets each memory section of the PE according to it's RWX flags
        private void SetSectionsMemoryPermissions() {

            // Iterate over all sections
            for (var i = 0; i < pe.FileHeader.NumberOfSections; i++) {
                IMAGE_SECTION_HEADER header = pe.ImageSectionHeaders[i];

                if (header.SizeOfRawData == 0) {
                    Logger.Log($"Section '{new string(header.Name)}' has no raw data", Logger.LogLevel.WARN);
                    continue;
                }

                var execute = ((uint)header.Characteristics & NativeBridge.IMAGE_SCN_MEM_EXECUTE) != 0;
                var read = ((uint)header.Characteristics & NativeBridge.IMAGE_SCN_MEM_READ) != 0;
                var write = ((uint)header.Characteristics & NativeBridge.IMAGE_SCN_MEM_WRITE) != 0;

                var protectionType = "PAGE_EXECUTE_READWRITE";
                var protection = NativeBridge.PAGE_EXECUTE_READWRITE;
                if (execute && read && write) {
                    protectionType = "PAGE_EXECUTE_READWRITE";
                    protection = NativeBridge.PAGE_EXECUTE_READWRITE;
                }
                else if (!execute && read && write) {
                    protectionType = "PAGE_READWRITE";
                    protection = NativeBridge.PAGE_READWRITE;
                }
                else if (!write && execute && read) {
                    protectionType = "PAGE_EXECUTE_READ";
                    protection = NativeBridge.PAGE_EXECUTE_READ;
                }
                else if (!execute && !write && read) {
                    protectionType = "PAGE_READONLY";
                    protection = NativeBridge.PAGE_READONLY;
                }
                else if (execute && !read && !write) {
                    protectionType = "PAGE_EXECUTE";
                    protection = NativeBridge.PAGE_EXECUTE;
                }
                else if (!execute && !read && !write) {
                    protectionType = "PAGE_NOACCESS";
                    protection = NativeBridge.PAGE_NOACCESS;
                }

                IntPtr memoryAddress = IntPtr.Add(baseAddress, (int) header.VirtualAddress);
                Logger.Log($"Set permissions {protectionType} on section '{new string(header.Name)}' (VirtualAddress: 0x{header.VirtualAddress:X} RealAddress: 0x{memoryAddress:X} Size: 0x{header.SizeOfRawData:X})", Logger.LogLevel.TRACE);

                if (!NativeBridge.VirtualProtect(memoryAddress, (UIntPtr)header.SizeOfRawData, protection, out _)) {
                    uint errorCode = NativeBridge.GetLastError();
                    throw new Exception($"Unable to protect virtual memory for {new string(header.Name)} (Type: {protectionType} VirtualAddress: 0x{header.VirtualAddress:X}, SizeOfRawData: 0x{header.SizeOfRawData:X})", new Win32Exception((int) errorCode));
                }
            }
        }

        // Patch the import table of the DLL with actual function call addresses
        private void PatchImportTable(DllLoader dllLoader) {

            foreach (var importFunction in this.importedFunctions) {

                // Load the imported library
                IntPtr dllModule = dllLoader.LoadLibrary(importFunction.DllName, dwFlags);

                long dllFunctionAddress = 0;

                // Import via name
                if (importFunction.Type == ImportedFunctionType.NAME) {

                    // Retrieve the address of the function within the Dll
                    dllFunctionAddress = NativeBridge.GetProcAddress(dllModule, importFunction.FunctionName).ToInt64();

                // Import via ordinal
                } else {

                    // Retrieve the address of the function within the Dll
                    dllFunctionAddress = NativeBridge.GetProcAddress(dllModule, importFunction.Ordinal).ToInt64();
                }

                // Retrieve the function address pointer that we want to patch
                IntPtr functionAddrPointer = importFunction.FunctionAddressPtr;

                // Overwrite the IMAGE_LOOKUP_ENTRY in the IAT to point to the actual function
                Marshal.WriteInt64(functionAddrPointer, dllFunctionAddress);

                Logger.Log($"Bound function pointer 0x{functionAddrPointer.ToInt64() - baseAddress.ToInt64():X} for '{importFunction.DllName}' "+ ((importFunction.Type == ImportedFunctionType.NAME)? $"name '{importFunction.FunctionName}'" : $"ordinal 0x{importFunction.Ordinal:X}") + $" to function address 0x{dllFunctionAddress:X}", Logger.LogLevel.TRACE);
            }
        }

        // Retrieve a list of all the imported functions from the PE
        private List<ImportedFunction> GetImportedFunctions() {
            /*
            -- Optional Header START --
            ...
            IMPORT_TABLE
                VirtualAddress  // Address of first IMAGE_IMPORT_DESCRIPTOR
                Size            // Size of all IMAGE_IMPORT_DESCRIPTORS
            -- Optional Header END --
            
            -- Virtual Address START --
                IMAGE_IMPORT_DESCRIPTOR
                    uint OriginalFirstThunk // Address of the Import Lookup Table (ILT) for this DLL
                    uint TimeDateStamp      // Timestamp of binding, 0 if not-yet-bound, -1 if initially bound, or the timestamp of binding if bound at runtime
                    uint ForwarderChain     // The index of the first forwarder chain reference
                    uint Name               // Address of the DLL name
                    uint FirstThunk         // Address of the Import Address Table (IAT) for this DLL
                ... repeats ...
                IMAGE_IMPORT_DESCRIPTOR
                    TODO
            -- Virtual Address END --

            -- Random Memory START --
                IMAGE_LOOKUP_TABLE
                    IMAGE_LOOKUP_ENTRY  // Address to a IMAGE_IMPORT_BY_NAME
                    IMAGE_LOOKUP_ENTRY
                    NULL
                ... repeats ...
            -- Random Memory END --

            -- Random Memory START --
                IMAGE_IMPORT_BY_NAME
                    int    hint            // If non-zero, the DLL functions ordinal to use
                        16-bit ordinal value
                        16-bit type
                    string dllFunctionName // Name of the DLL function, used if hint is zero
            -- Random Memory END --

            -- Import Address Table --
                IMAGE_ADDRESS_TABLE
                    IMAGE_LOOKUP_ENTRY  // Address to a IMAGE_IMPORT_BY_NAME
                    IMAGE_LOOKUP_ENTRY
                    NULL entry
                ... repeats ...
            -- Import Address Table --
            */

            List<ImportedFunction> importedFunctions = new List<ImportedFunction>();

            if(pe.OptionalHeader64.ImportTable.Size == 0) {
                Logger.Log($"ImportTable is empty", Logger.LogLevel.TRACE);
                return importedFunctions;
            }

            Logger.Log($"ImportTable VirtualAddress: 0x{pe.OptionalHeader64.ImportTable.VirtualAddress:X} - 0x{pe.OptionalHeader64.ImportTable.VirtualAddress + pe.OptionalHeader64.ImportTable.Size:X}", Logger.LogLevel.TRACE);

            var SIZE_OF_IMAGE_IMPORT_DESCRIPTOR_STRUCT = (uint)Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
            
            // Iterate over the IMAGE_IMPORT_DESCRIPTORS
            // NOTE: The last IMAGE_IMPORT_DESCRIPTOR of the array is zeroed-out (NULL-Padded) to indicate the end of the Import Directory Table.
            for (uint importDescriptorOffset = pe.OptionalHeader64.ImportTable.VirtualAddress; importDescriptorOffset < (pe.OptionalHeader64.ImportTable.VirtualAddress + pe.OptionalHeader64.ImportTable.Size - SIZE_OF_IMAGE_IMPORT_DESCRIPTOR_STRUCT); importDescriptorOffset += SIZE_OF_IMAGE_IMPORT_DESCRIPTOR_STRUCT) {

                // Retrieve the IMAGE_IMPORT_DESCRIPTOR
                IMAGE_IMPORT_DESCRIPTOR importDescriptor = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(IntPtr.Add(baseAddress, (int)importDescriptorOffset), typeof(IMAGE_IMPORT_DESCRIPTOR));

                if (importDescriptor.Name == 0) {
                    Logger.Log($"IMAGE_IMPORT_DESCRIPTOR is corrupt for {this.BaseAddress}", Logger.LogLevel.WARN);
                    throw new Exception($"IMAGE_IMPORT_DESCRIPTOR is corrupt for {this.BaseAddress}");
                }

                string importDllName = Marshal.PtrToStringAnsi(IntPtr.Add(baseAddress, (int)importDescriptor.Name));

                Logger.Log($"IMAGE_IMPORT_DESCRIPTORS at 0x{importDescriptorOffset:X} (ForwarderChain: 0x{importDescriptor.ForwarderChain:X} OriginalFirstThunk: 0x{importDescriptor.OriginalFirstThunk:X}  TimeDateStamp: 0x{importDescriptor.TimeDateStamp:X} NameAddress: 0x{importDescriptor.Name:X} Name: '{importDllName}' FirstThunk: 0x{importDescriptor.FirstThunk:X})", Logger.LogLevel.TRACE);

                // Iterate through the IMAGE_LOOKUP_ENTRY in the Image Lookup Table (ILT, Original Thunk) and not the Image Address Table (IAT, Thunk)
                for (uint imageLookupEntryAddress = importDescriptor.OriginalFirstThunk; true; imageLookupEntryAddress += (uint)IntPtr.Size) {
                    long imageImportByNameAddress = Marshal.ReadInt64(IntPtr.Add(baseAddress, (int)imageLookupEntryAddress));

                    // The array of IMAGE_LOOKUP_ENTRYs is terminated with an all-zero entry
                    if (imageImportByNameAddress == 0) {
                        break;
                    }

                    Logger.Log($"IMAGE_LOOKUP_ENTRY at address 0x{imageLookupEntryAddress:X} (VirtualAddress: 0x{imageLookupEntryAddress:X} AbsoluteAddress: 0x{imageImportByNameAddress:X})", Logger.LogLevel.TRACE);

                    string dllFunctionName = "";
                    ushort ordinal;

                    // First bit is Ordinal/Name flag
                    // 0 = Name
                    // 1 = Ordinal
                    ImportedFunctionType entryType = (ImportedFunctionType) ((imageImportByNameAddress & 1 << 63) != 0 ? 1 : 0);

                    // Import by ordinal
                    if (entryType == ImportedFunctionType.ORDINAL) {
                        Logger.Log($"Import by ordinal found", Logger.LogLevel.TRACE);
                        ordinal = (ushort)(imageImportByNameAddress & 0xFFFF);

                    // Import by name
                    }else{
                        Logger.Log($"IMAGE_LOOKUP_ENTRY found", Logger.LogLevel.TRACE);

                        // Retrieve the hint field
                        ushort hint = (ushort) Marshal.ReadInt16(IntPtr.Add(baseAddress, (int)imageImportByNameAddress));
                        ordinal = hint;

                        // Retrieve the IMAGE_IMPORT_BY_NAME 'dllName' field
                        dllFunctionName = Marshal.PtrToStringAnsi(IntPtr.Add(baseAddress, (int)imageImportByNameAddress + sizeof(Int16)));

                        // Hit the end
                        if (string.IsNullOrEmpty(importDllName)) {
                            break;
                        }
                    }

                    // NOTE: While we are looping over the ILT (which doesn't change at runtime) we
                    // want to expose the FunctionAddressPtr which references the IAT which DOES change
                    // at runtime when imported functions are mapped.
                    IntPtr iatFunctionPtr = IntPtr.Add(baseAddress, (int)(importDescriptor.FirstThunk + (imageLookupEntryAddress - importDescriptor.OriginalFirstThunk)));

                    importedFunctions.Add(
                        new ImportedFunction {
                            Type = entryType,
                            Ordinal = ordinal,
                            DllName = importDllName,
                            FunctionName = dllFunctionName,
                            FunctionAddressPtr = iatFunctionPtr,
                        });

                    Logger.Log($"Found import function (Type: {entryType} Ordinal: 0x{ordinal:x} DllName: '{importDllName}' FunctionName: '{dllFunctionName}' FunctionAddressPtr: 0x{iatFunctionPtr.ToInt64() - baseAddress.ToInt64():X})", Logger.LogLevel.TRACE);
                }
            }

            return importedFunctions;
        }

        // Retrieve all the exported functions from the PE
        private List<ExportedFunction> GetExportedFunctions(DllLoader dllLoader) {

            var exportedFunctions = new Dictionary<string, ExportedFunction>();

            Logger.Log($"ExportTable Virtual Address 0x{pe.optionalHeader64.ExportTable.VirtualAddress:X} - 0x{pe.optionalHeader64.ExportTable.VirtualAddress+ pe.optionalHeader64.ExportTable.Size:X}", Logger.LogLevel.TRACE);

            // Get the exported functions
            if (pe.optionalHeader64.ExportTable.Size > 0) {

                long exportTableAddress = baseAddress.ToInt64() + pe.optionalHeader64.ExportTable.VirtualAddress;
                IMAGE_EXPORT_DIRECTORY imageExportDirectory = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(new IntPtr(exportTableAddress), typeof(IMAGE_EXPORT_DIRECTORY));
                
                for (int i = 0; i < imageExportDirectory.NumberOfNames; i++) {
                    long functionNameAddressPtr = baseAddress.ToInt64() + (uint)(imageExportDirectory.AddressOfNames + (i * sizeof(uint)));

                    long functionNameAddress = baseAddress.ToInt64() + Marshal.ReadInt32(new IntPtr(functionNameAddressPtr));
                    string functionName = Marshal.PtrToStringAnsi(new IntPtr(functionNameAddress));

                    long ordinalAddress = baseAddress.ToInt64() + imageExportDirectory.AddressOfNameOrdinals + (i * sizeof(UInt16));
                    UInt16 ordinal = (UInt16) (imageExportDirectory.Base + Marshal.ReadInt16(new IntPtr(ordinalAddress))); // Note: Ordinals start at the Base

                    long functionAddressPtr = baseAddress.ToInt64() + imageExportDirectory.AddressOfFunctions + ((ordinal- imageExportDirectory.Base) * sizeof(uint));
                    int virtualFunctionAddress = Marshal.ReadInt32(new IntPtr(functionAddressPtr));

                    Logger.Log($"Found export function (AddressPtr: 0x{functionAddressPtr:X} VirtualAddress: 0x{virtualFunctionAddress:X} Ordinal: 0x{ordinal:X} Name: '{functionName}', FileName: '{this.fileName}')", Logger.LogLevel.TRACE);

                    IntPtr functionAddress = new IntPtr(baseAddress.ToInt64() + virtualFunctionAddress);

                    ExportedFunction exportedFunction = new ExportedFunction {
                        Ordinal = ordinal,
                        FunctionName = functionName,
                        FunctionAddress = functionAddress,
                    };

                    // Detect forwarded functions by determining if the address is inside the export table
                    if ((virtualFunctionAddress > pe.optionalHeader64.ExportTable.VirtualAddress) && virtualFunctionAddress < (pe.optionalHeader64.ExportTable.VirtualAddress + pe.optionalHeader64.ExportTable.Size)) {

                        // Parse out the dll and function name
                        string forwardedDllAndFunction = Marshal.PtrToStringAnsi(IntPtr.Add(baseAddress, virtualFunctionAddress));
                        string[] split = forwardedDllAndFunction.Split(new char[] { '.' }, (int) 2, StringSplitOptions.None);
                        string forwardedDllName;
                        string forwardedFunctionName;

                        // References another DLL
                        if (split.Length == 2) {
                            forwardedDllName = split[0] + ".dll";
                            forwardedFunctionName = split[1];

                        // References self
                        } else {
                            forwardedDllName = string.Empty;
                            forwardedFunctionName = forwardedDllAndFunction;
                        }
     
                        exportedFunction.ForwardedFunction = true;
                        exportedFunction.ForwardedFileName = forwardedDllName;
                        exportedFunction.ForwardedFunctionName = forwardedFunctionName;
                    }

                    exportedFunctions.Add(exportedFunction.FunctionName, exportedFunction);
                }

                // Resolve forwarded functions
                // NOTE: We do this after all functions have been identified because they can reference other functions within this dll
                for(int i=0; i<exportedFunctions.Count; i++) {
                    ExportedFunction exportedFunction = exportedFunctions.Values.ToArray()[i];

                    if (exportedFunction.ForwardedFunction) {
                        Logger.Log($"Found forwarded function: '{this.fileName}!{exportedFunction.FunctionName}' -> '{exportedFunction.ForwardedFileName}!{exportedFunction.ForwardedFunctionName}'", Logger.LogLevel.TRACE);

                        // Self reference
                        if (exportedFunction.ForwardedFileName == this.fileName) {
                            var targetFunction = exportedFunctions[exportedFunction.FunctionName];
                            if (targetFunction.ForwardedFunction) {
                                Logger.Log($"Function forwards to itself: '{this.fileName}!{exportedFunction.FunctionName}'", Logger.LogLevel.ERROR);
                            }
                            exportedFunction.FunctionAddress = targetFunction.FunctionAddress;

                         // External reference
                        } else {

                            IntPtr module = dllLoader.LoadLibrary(exportedFunction.ForwardedFileName, dwFlags);
                            IntPtr func = NativeBridge.GetProcAddress(module, exportedFunction.FunctionName);
                            exportedFunction.FunctionAddress = func;
                        }

                        // Structs are immutable, replace the entire record
                        exportedFunctions.Remove(exportedFunction.FunctionName);
                        exportedFunctions.Add(exportedFunction.FunctionName, exportedFunction);
                    }
                }
            }

            return exportedFunctions.Values.ToList();
        }

        // Retrieve a list of all TLS callback function addresses
        public List<IntPtr> GetTlsFunctionAddresses() {

            List<IntPtr> addresses = new List<IntPtr>();

            if (OptionalHeader.TLSTable.Size > 0) {
                var pTlsDirectory = new IntPtr(BaseAddress.ToInt64() + OptionalHeader.TLSTable.VirtualAddress);
                Logger.Log($"TLSTable.VirtualAddress 0x:{OptionalHeader.TLSTable.VirtualAddress:X}", Logger.LogLevel.TRACE);
                Logger.Log($"pTlsDirectory 0x:{pTlsDirectory:X}", Logger.LogLevel.TRACE);

                ImageTlsDirectory64 tlsDirectory = Marshal.PtrToStructure<ImageTlsDirectory64>(pTlsDirectory);
                Logger.Log($"StartAddressOfRawData 0x:{tlsDirectory.StartAddressOfRawData.ToInt64() - BaseAddress.ToInt64():X}", Logger.LogLevel.TRACE);
                Logger.Log($"EndAddressOfRawData 0x:{tlsDirectory.EndAddressOfRawData.ToInt64() - BaseAddress.ToInt64():X}", Logger.LogLevel.TRACE);
                Logger.Log($"AddressOfIndex 0x:{tlsDirectory.AddressOfIndex.ToInt64() - BaseAddress.ToInt64():X}", Logger.LogLevel.TRACE);
                Logger.Log($"AddressOfCallBacks 0x:{tlsDirectory.AddressOfCallBacks.ToInt64() - BaseAddress.ToInt64():X}", Logger.LogLevel.TRACE);
                Logger.Log($"SizeOfZeroFill 0x:{tlsDirectory.SizeOfZeroFill:X}", Logger.LogLevel.TRACE);
                Logger.Log($"Characteristics 0x:{tlsDirectory.Characteristics:X}", Logger.LogLevel.TRACE);

                for (int offset = 0; ; offset += 0x08) { // x64 specific pointer size
                    var tlsFunctionAddress = Marshal.ReadIntPtr(tlsDirectory.AddressOfCallBacks + offset);

                    // Hit the end
                    if (tlsFunctionAddress == IntPtr.Zero) {
                        break;
                    }

                    Logger.Log($"tlsFunctionAddress 0x:{tlsFunctionAddress.ToInt64() - BaseAddress.ToInt64():X}", Logger.LogLevel.TRACE);
                    addresses.Add(tlsFunctionAddress);
                }
            }

            return addresses;
        }

        // Patches the relocation table based on where we wrote the PE into memory
        private void PatchRelocationTable() {
            /*
            -- Optional Header START --
            ...
            RELOCATION_TABLE
                VirtualAddress // Address of RELOCATION_BLOCK
                Size
            -- Optional Header END --

            -- Virtual Address START --
                RELOCATION_BLOCK
                    uint VirtualAddress // Virtual base for the offsets that follow
                    uint SizeOfBlock    // Size of the RELOCATION_ENTRIES
                    RELOCATION_ENTRY
                        4-bits type     // Relocation type (eg R_AMD64_32)
                        12-bits offset  // Offset to be added to the RELOCATION_BLOCK VirtualAddress
                    ... repeats ...
                    RELOCATION_ENTRY
                        4-bits type
                        12-bits offset       
                ... repeats ...
                RELOCATION_BLOCK
                    uint VirtualAddress
                    uint SizeOfBlock
                    RELOCATION_ENTRY
                        4-bits type
                        12-bits offset
                    ... repeats ...
                    RELOCATION_ENTRY
                        4-bits type
                        12-bits offset
            -- Virtual Address END --
            */

            var SIZE_OF_RELOCATION_BLOCK_STRUCT = (uint) Marshal.SizeOf(typeof(NativeBridge.IMAGE_BASE_RELOCATION));

            // Find RELOCATION_TABLE
            var relocationTable = IntPtr.Add(baseAddress, (int) pe.OptionalHeader64.BaseRelocationTable.VirtualAddress);

            Logger.Log($"Base Relocation Table at 0x{pe.OptionalHeader64.BaseRelocationTable.VirtualAddress:X} - 0x{pe.OptionalHeader64.BaseRelocationTable.VirtualAddress + pe.OptionalHeader64.BaseRelocationTable.Size:X}", Logger.LogLevel.TRACE);

            // Iterate over the RELOCAT_BLOCKS
            NativeBridge.IMAGE_BASE_RELOCATION relocationBlock = new NativeBridge.IMAGE_BASE_RELOCATION { }; // Unused until looped
            for (uint relocationBlockOffset = 0; relocationBlockOffset < pe.OptionalHeader64.BaseRelocationTable.Size; relocationBlockOffset += relocationBlock.SizeOfBlock) {

                // Retrieve the RELOCATION_BLOCK
                relocationBlock = (NativeBridge.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(IntPtr.Add(relocationTable, (int)relocationBlockOffset), typeof(NativeBridge.IMAGE_BASE_RELOCATION));

                Logger.Log($"RELOCATION_BLOCK (SizeOfBlock: 0x{relocationBlock.SizeOfBlock:X} BaseOffset: 0x{relocationBlock.BaseOffset:X})", Logger.LogLevel.TRACE);

                // The RELOCATION_ENTRIES is after the RELOCATION_BLOCK
                uint relocationEntryOffset = relocationBlockOffset + SIZE_OF_RELOCATION_BLOCK_STRUCT;

                // Iterate over all RELOCATION_ENTRIES that fit inside the RELOCATION_BLOCK size
                for (; relocationEntryOffset < (relocationBlockOffset + relocationBlock.SizeOfBlock); relocationEntryOffset += sizeof(ushort)) {

                    // Retrieve the RELOCATION_ENTRY
                    ushort entryValue = (ushort) Marshal.ReadInt16(IntPtr.Add(relocationTable, (int)relocationEntryOffset));

                    // First byte is the "type"
                    ushort type = (ushort)((entryValue & 0xF000) >> 12);

                    // Remaining 3 bytes are the "offset"
                    ushort relativeOffset = (ushort)(entryValue & 0x0FFF);

                    Logger.Log($"RELOCATION_ENTRY (Type: 0x{type:X} Offset: 0x{relativeOffset:X}) at relative address 0x{ relocationTable.ToInt64() + relocationEntryOffset - baseAddress.ToInt64():X}", Logger.LogLevel.TRACE);

                    switch (type) {

                        // R_386_NONE
                        case 0x0:
                            // Padding
                            break;

                        // R_AMD64_32
                        case 0xA:

                            // Combine the base RELOCATION_BLOCK offset with the RELOCATION_ENTRY offset to get the offset from base
                            // Add the (dynamic) base to get the true in memory location
                            long absoluteOffset = relativeOffset + relocationBlock.BaseOffset + baseAddress.ToInt64();

                            // Retrieve the old address that is relative to the OptionalHeader64.ImageBase
                            long originalAddress = Marshal.ReadInt64(new IntPtr(absoluteOffset));

                            // Calculate the difference between the PE image base address and the true (dynamic) address once placed in memory
                            long delta = baseAddress.ToInt64() - (long) pe.OptionalHeader64.ImageBase;

                            // Apply the delta to create a new value that is correct relative to where this DLL was placed in memory
                            long newAddress = originalAddress + delta;

                            // Update the value
                            Marshal.WriteInt64(new IntPtr(absoluteOffset), newAddress);

                            Logger.Log($"RELOCATION_ENTRY at 0x{(relativeOffset + relocationBlock.BaseOffset):X} (existing value 0x{originalAddress:X}) was updated to 0x{newAddress:X}", Logger.LogLevel.TRACE);

                            break;
                        default:
                            throw new Exception($"Relocation table contains a relocation entry with an unsupported type 0x{type:X} at virtual address 0x{entryValue - baseAddress.ToInt64():X}");
                    }
                }
            }
        }
    }

    public struct ImportedFunction {
        public ImportedFunctionType Type;
        public UInt16 Ordinal;
        public string DllName;
        public string FunctionName;
        public IntPtr FunctionAddressPtr; // ABSOLUTE: The location of a pointer to the actual function address
    }

    public enum ImportedFunctionType {
        NAME = 0,
        ORDINAL = 1,
    }

    public struct ExportedFunction {
        public UInt16 Ordinal;
        public string FunctionName;
        public IntPtr FunctionAddress; // ABSOLUTE: The location of the actual function address
        public bool ForwardedFunction;
        public string ForwardedFileName;
        public string ForwardedFunctionName;
    }
}