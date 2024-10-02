using System;
using System.IO;
using System.Runtime.InteropServices;

// Based on https://github.com/nettitude/RunPE/blob/main/RunPE/Internals/PELoader.cs
namespace Silverton.Core.Image {

    public class PEImage {

        /// The DOS header
        internal IMAGE_DOS_HEADER dosHeader;

        /// The file header
        internal IMAGE_FILE_HEADER fileHeader;

        /// Optional 32 bit file header 
        internal IMAGE_OPTIONAL_HEADER32 optionalHeader32;

        /// Optional 64 bit file header 
        internal IMAGE_OPTIONAL_HEADER64 optionalHeader64;

        /// Image Section headers. Number of sections is in the file header.
        internal IMAGE_SECTION_HEADER[] imageSectionHeaders;

        internal bool is32Bit = false;

        internal bool Is32Bit {
            get {
                return this.is32Bit;
            }
        }

        public IMAGE_FILE_HEADER FileHeader {
            get { return fileHeader; }
        }

        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64 {
            get { return optionalHeader64; }
        }

        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32 {
            get { return optionalHeader32; }
        }

        public IMAGE_SECTION_HEADER[] ImageSectionHeaders {
            get { return imageSectionHeaders; }
        }

        public static class PEReader {

            public static PEImage ParseLoadedModule(IntPtr moduleHandle) {

                // Retrieve the NT header location
                int ntHeaderLocation = Marshal.ReadInt32(IntPtr.Add(moduleHandle, 0x3C));

                // Retrieve the length of the header ...
                long headersSize = Marshal.ReadInt32(IntPtr.Add(moduleHandle, ntHeaderLocation + 0x54));

                // Copy the headers to memory
                byte[] peHeader = new byte[headersSize];
                Marshal.Copy(moduleHandle, peHeader, 0, peHeader.Length);

                // Read them using the PE Reader
                PEImage pe = PEImage.PEReader.ParseHeader(peHeader);

                return pe;
            }

            public static PEImage ParseHeader(byte[] fileBytes) {

                PEImage pe = new PEImage();

                using (var stream = new MemoryStream(fileBytes, 0, fileBytes.Length)) {
                    var reader = new BinaryReader(stream);
                    pe.dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                    stream.Seek(pe.dosHeader.e_lfanew, SeekOrigin.Begin);

                    var ntHeadersSignature = reader.ReadUInt32();
                    if (ntHeadersSignature != 0x4550) {
                        throw new Exception($"NT Header Signature incorrect: 0x{ntHeadersSignature:X}");
                    }

                    pe.fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);

                    var seekOffset = stream.Position;
                    var optionalHeaderSignature = reader.ReadUInt16();
                    stream.Seek(seekOffset, SeekOrigin.Begin);

                    if (optionalHeaderSignature == 0x10B) {
                        pe.is32Bit = true;
                        pe.optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                    }
                    else if(optionalHeaderSignature == 0x20B) {
                        pe.is32Bit = false;
                        pe.optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                    } else {
                        throw new Exception($"Unknown optional header signature: 0x{optionalHeaderSignature:X}");
                    }

                    pe.imageSectionHeaders = new IMAGE_SECTION_HEADER[pe.fileHeader.NumberOfSections];
                    for (var headerNo = 0; headerNo < pe.imageSectionHeaders.Length; ++headerNo) {
                        pe.imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                    }
                }

                return pe;
            }

            private static T FromBinaryReader<T>(BinaryReader reader) {
                var bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
                var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
                var theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                handle.Free();
                return theStructure;
            }

        }
    }
    public struct IMAGE_DOS_HEADER {
        // DOS .EXE header
        public ushort e_magic; // Magic number
        public ushort e_cblp; // Bytes on last page of file
        public ushort e_cp; // Pages in file
        public ushort e_crlc; // Relocations
        public ushort e_cparhdr; // Size of header in paragraphs
        public ushort e_minalloc; // Minimum extra paragraphs needed
        public ushort e_maxalloc; // Maximum extra paragraphs needed
        public ushort e_ss; // Initial (relative) SS value
        public ushort e_sp; // Initial SP value
        public ushort e_csum; // Checksum
        public ushort e_ip; // Initial IP value
        public ushort e_cs; // Initial (relative) CS value
        public ushort e_lfarlc; // File address of relocation table
        public ushort e_ovno; // Overlay number
        public ushort e_res_0; // Reserved words
        public ushort e_res_1; // Reserved words
        public ushort e_res_2; // Reserved words
        public ushort e_res_3; // Reserved words
        public ushort e_oemid; // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo; // OEM information; e_oemid specific
        public ushort e_res2_0; // Reserved words
        public ushort e_res2_1; // Reserved words
        public ushort e_res2_2; // Reserved words
        public ushort e_res2_3; // Reserved words
        public ushort e_res2_4; // Reserved words
        public ushort e_res2_5; // Reserved words
        public ushort e_res2_6; // Reserved words
        public ushort e_res2_7; // Reserved words
        public ushort e_res2_8; // Reserved words
        public ushort e_res2_9; // Reserved words
        public uint e_lfanew; // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32 {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_IMPORT_DESCRIPTOR {
        #region union
        /// <summary>
        /// CSharp doesnt really support unions, but they can be emulated by a field offset 0
        /// </summary>

        [FieldOffset(0)]
        public uint Characteristics;            // 0 for terminating null import descriptor
        [FieldOffset(0)]
        public uint OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
        #endregion

        [FieldOffset(4)]
        public uint TimeDateStamp;
        [FieldOffset(8)]
        public uint ForwarderChain;
        [FieldOffset(12)]
        public uint Name;
        [FieldOffset(16)]
        public uint FirstThunk;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64 {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY ImportAddressTable;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;

        [FieldOffset(8)] public uint VirtualSize;
        [FieldOffset(12)] public uint VirtualAddress;
        [FieldOffset(16)] public uint SizeOfRawData;
        [FieldOffset(20)] public uint PointerToRawData;
        [FieldOffset(24)] public uint PointerToRelocations;
        [FieldOffset(28)] public uint PointerToLinenumbers;
        [FieldOffset(32)] public ushort NumberOfRelocations;
        [FieldOffset(34)] public ushort NumberOfLinenumbers;
        [FieldOffset(36)] public DataSectionFlags Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY {
        public UInt32 Characteristics;
        public UInt32 TimeDateStamp;
        public UInt16 MajorVersion;
        public UInt16 MinorVersion;
        public UInt32 Name;
        public UInt32 Base;
        public UInt32 NumberOfFunctions;
        public UInt32 NumberOfNames;
        public UInt32 AddressOfFunctions; // RVA from base of image
        public UInt32 AddressOfNames; // RVA from base of image
        public UInt32 AddressOfNameOrdinals; // RVA from base of image
    }

    [Flags]
    public enum DataSectionFlags : uint {
        Stub = 0x00000000,
    }
}