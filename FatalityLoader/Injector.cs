using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;

namespace FatalityLoader
{
    public static class Injector
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint dwFreeType);

        [DllImport("kernel32.dll")]
        static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetModuleHandleEx(uint dwFlags, IntPtr lpModuleName, out IntPtr phModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern uint GetModuleFileName(IntPtr hModule, StringBuilder lpFilename, int nSize);

        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibraryA(string lpFileName);

        const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint MEM_RELEASE = 0x8000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_READWRITE = 0x04;

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 29)]
            public ushort[] e_res;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
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
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAddress;
            public uint SizeOfBlock;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_TLS_DIRECTORY64
        {
            public ulong StartAddressOfRawData;
            public ulong EndAddressOfRawData;
            public ulong AddressOfIndex;
            public ulong AddressOfCallBacks;
            public uint SizeOfZeroFill;
            public uint Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RUNTIME_FUNCTION
        {
            public uint BeginAddress;
            public uint EndAddress;
            public uint UnwindData;
        }

        public static string? Inject(string processName, byte[] dllBytes)
        {
            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0) return "Process not found";
            Process target = processes[0];

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, target.Id);
            if (hProcess == IntPtr.Zero) return "OpenProcess failed (Access Denied?)";

            GCHandle pinnedDll = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
            IntPtr pDll = pinnedDll.AddrOfPinnedObject();
            
            IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(pDll);
            if (dosHeader.e_magic != 0x5A4D) return "Invalid DLL (MZ missing)";

            IntPtr pNtHeaders = pDll + dosHeader.e_lfanew;
            IMAGE_NT_HEADERS64 ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(pNtHeaders);

            if (ntHeaders.OptionalHeader.Magic != 0x20B) return "DLL is not x64";

            IntPtr pRemoteImage = VirtualAllocEx(hProcess, IntPtr.Zero, ntHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pRemoteImage == IntPtr.Zero) return "VirtualAllocEx failed";

            WriteProcessMemory(hProcess, pRemoteImage, dllBytes, (int)ntHeaders.OptionalHeader.SizeOfHeaders, out _);

            IntPtr pSectionHeader = pNtHeaders + Marshal.SizeOf(typeof(uint)) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) + ntHeaders.FileHeader.SizeOfOptionalHeader;
            
            for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
            {
                IMAGE_SECTION_HEADER section = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(pSectionHeader + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))));
                
                if (section.SizeOfRawData > 0)
                {
                    byte[] sectionData = new byte[section.SizeOfRawData];
                    Array.Copy(dllBytes, section.PointerToRawData, sectionData, 0, section.SizeOfRawData);
                    WriteProcessMemory(hProcess, pRemoteImage + (int)section.VirtualAddress, sectionData, (int)section.SizeOfRawData, out _);
                }
            }

            long delta = (long)pRemoteImage - (long)ntHeaders.OptionalHeader.ImageBase;
            if (delta != 0 && ntHeaders.OptionalHeader.DataDirectory[5].Size > 0)
            {
                uint relocSize = ntHeaders.OptionalHeader.DataDirectory[5].Size;
                uint relocAddr = ntHeaders.OptionalHeader.DataDirectory[5].VirtualAddress;
                
                int offset = 0;
                while (offset < relocSize)
                {
                    uint rva = relocAddr + (uint)offset;
                    uint fileOffset = RvaToOffset(rva, ntHeaders.FileHeader.NumberOfSections, pSectionHeader);
                    
                    if (fileOffset == 0) break;

                    IMAGE_BASE_RELOCATION relocation = Marshal.PtrToStructure<IMAGE_BASE_RELOCATION>(pDll + (int)fileOffset);
                    if (relocation.SizeOfBlock == 0) break;

                    int entriesCount = (int)((relocation.SizeOfBlock - Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION))) / 2);
                    
                    for (int j = 0; j < entriesCount; j++)
                    {
                        ushort typeOffset = Marshal.PtrToStructure<ushort>(pDll + (int)fileOffset + Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION)) + (j * 2));
                        int type = typeOffset >> 12;
                        int relOffset = typeOffset & 0xFFF;

                        if (type == 10)
                        {
                            IntPtr patchAddr = pRemoteImage + (int)relocation.VirtualAddress + relOffset;
                            byte[] buff = new byte[8];
                            ReadProcessMemory(hProcess, patchAddr, buff, 8, out _);
                            long val = BitConverter.ToInt64(buff, 0);
                            val += delta;
                            WriteProcessMemory(hProcess, patchAddr, BitConverter.GetBytes(val), 8, out _);
                        }
                    }
                    offset += (int)relocation.SizeOfBlock;
                }
            }

            if (ntHeaders.OptionalHeader.DataDirectory[1].Size > 0)
            {
                uint importAddr = ntHeaders.OptionalHeader.DataDirectory[1].VirtualAddress;
                uint fileOffset = RvaToOffset(importAddr, ntHeaders.FileHeader.NumberOfSections, pSectionHeader);
                
                int offset = 0;
                while (true)
                {
                    IMAGE_IMPORT_DESCRIPTOR importDesc = Marshal.PtrToStructure<IMAGE_IMPORT_DESCRIPTOR>(pDll + (int)fileOffset + offset);
                    if (importDesc.Name == 0) break;

                    uint nameOffset = RvaToOffset(importDesc.Name, ntHeaders.FileHeader.NumberOfSections, pSectionHeader);
                    string moduleName = Marshal.PtrToStringAnsi(pDll + (int)nameOffset);
                    
                    IntPtr hLocalModule = LoadLibraryA(moduleName);
                    if (hLocalModule == IntPtr.Zero) return $"Failed to load dependency locally: {moduleName}";

                    uint thunkRef = importDesc.OriginalFirstThunk == 0 ? importDesc.FirstThunk : importDesc.OriginalFirstThunk;
                    uint funcRef = importDesc.FirstThunk;

                    uint thunkOffset = RvaToOffset(thunkRef, ntHeaders.FileHeader.NumberOfSections, pSectionHeader);

                    int thunkIdx = 0;
                    while (true)
                    {
                        ulong thunkData = Marshal.PtrToStructure<ulong>(pDll + (int)thunkOffset + (thunkIdx * 8));
                        if (thunkData == 0) break;

                        IntPtr localFuncAddr = IntPtr.Zero;
                        string funcNameForDebug = "";

                        if ((thunkData & 0x8000000000000000) != 0)
                        {
                            short ordinal = (short)(thunkData & 0xFFFF);
                            localFuncAddr = GetProcAddress(hLocalModule, (IntPtr)ordinal);
                            funcNameForDebug = $"#{ordinal}";
                        }
                        else
                        {
                            uint nameDataOffset = RvaToOffset((uint)(thunkData & 0xFFFFFFFF), ntHeaders.FileHeader.NumberOfSections, pSectionHeader);
                            string funcName = Marshal.PtrToStringAnsi(pDll + (int)nameDataOffset + 2);
                            localFuncAddr = GetProcAddress(hLocalModule, funcName);
                            funcNameForDebug = funcName;
                        }

                        if (localFuncAddr == IntPtr.Zero) return $"Failed to resolve function: {funcNameForDebug} in {moduleName}";

                        IntPtr hRealMod = IntPtr.Zero;
                        if (!GetModuleHandleEx(6, localFuncAddr, out hRealMod))
                        {
                            hRealMod = hLocalModule;
                        }

                        StringBuilder realModNameSb = new StringBuilder(1024);
                        GetModuleFileName(hRealMod, realModNameSb, realModNameSb.Capacity);
                        string realModPath = realModNameSb.ToString();
                        string realModName = Path.GetFileName(realModPath);

                        IntPtr hRemoteRealMod = GetRemoteModuleHandle(target, realModName);
                        if (hRemoteRealMod == IntPtr.Zero)
                        {
                            LoadRemoteLibrary(hProcess, realModName);
                            target.Refresh();
                            hRemoteRealMod = GetRemoteModuleHandle(target, realModName);
                        }

                        if (hRemoteRealMod == IntPtr.Zero) return $"Could not load dependency in remote: {realModName}";

                        long funcOffset = (long)localFuncAddr - (long)hRealMod;
                        IntPtr remoteFuncAddr = (IntPtr)((long)hRemoteRealMod + funcOffset);

                        WriteProcessMemory(hProcess, pRemoteImage + (int)funcRef + (thunkIdx * 8), BitConverter.GetBytes(remoteFuncAddr.ToInt64()), 8, out _);

                        thunkIdx++;
                    }
                    offset += Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR));
                }
            }

            IntPtr pRtlAddFunctionTable = GetProcAddress(GetModuleHandle("kernel32.dll"), "RtlAddFunctionTable");
            if (pRtlAddFunctionTable == IntPtr.Zero)
                pRtlAddFunctionTable = GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlAddFunctionTable");

            List<IntPtr> executionList = new List<IntPtr>();
            
            uint exceptionDirSize = ntHeaders.OptionalHeader.DataDirectory[3].Size;
            uint exceptionDirRva = ntHeaders.OptionalHeader.DataDirectory[3].VirtualAddress;
            
            bool enableSEH = false;
            IntPtr pExceptionTable = pRemoteImage + (int)exceptionDirRva;
            uint entryCount = exceptionDirSize / (uint)Marshal.SizeOf(typeof(RUNTIME_FUNCTION));

            if (ntHeaders.OptionalHeader.DataDirectory[9].Size > 0)
            {
                uint tlsRva = ntHeaders.OptionalHeader.DataDirectory[9].VirtualAddress;
                uint tlsFileOffset = RvaToOffset(tlsRva, ntHeaders.FileHeader.NumberOfSections, pSectionHeader);
                IMAGE_TLS_DIRECTORY64 tlsDir = Marshal.PtrToStructure<IMAGE_TLS_DIRECTORY64>(pDll + (int)tlsFileOffset);
                
                if (tlsDir.AddressOfCallBacks != 0)
                {
                    ulong originalImageBase = ntHeaders.OptionalHeader.ImageBase;
                    uint callbacksRva = (uint)(tlsDir.AddressOfCallBacks - originalImageBase);
                    uint callbacksFileOffset = RvaToOffset(callbacksRva, ntHeaders.FileHeader.NumberOfSections, pSectionHeader);
                    
                    int idx = 0;
                    while (true)
                    {
                        ulong callbackVa = Marshal.PtrToStructure<ulong>(pDll + (int)callbacksFileOffset + (idx * 8));
                        if (callbackVa == 0) break;
                        IntPtr remoteCallback = (IntPtr)(pRemoteImage.ToInt64() + (long)(callbackVa - originalImageBase));
                        executionList.Add(remoteCallback);
                        idx++;
                    }
                }
            }

            IntPtr pEntryPoint = pRemoteImage + (int)ntHeaders.OptionalHeader.AddressOfEntryPoint;
            executionList.Add(pEntryPoint);

            string? err = ExecuteRemoteBatch(hProcess, executionList, pRemoteImage, enableSEH, pRtlAddFunctionTable, pExceptionTable, entryCount);
            if (err != null) return err;
            
            pinnedDll.Free();
            return null;
        }

        static string? ExecuteRemoteBatch(IntPtr hProcess, List<IntPtr> functions, IntPtr moduleBase, bool enableSEH, IntPtr pRtlAddFunctionTable, IntPtr pExceptionTable, uint entryCount)
        {
            IntPtr pShellcode = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pShellcode == IntPtr.Zero) return "VirtualAllocEx (Shellcode) failed";

            int listSize = functions.Count * 8;
            IntPtr pFuncList = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)listSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            long[] funcArray = functions.Select(x => x.ToInt64()).ToArray();
            byte[] listBytes = new byte[listSize];
            Buffer.BlockCopy(funcArray, 0, listBytes, 0, listSize);
            WriteProcessMemory(hProcess, pFuncList, listBytes, listSize, out _);

            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(ms))
            {
                writer.Write(new byte[] { 0x48, 0x83, 0xEC, 0x28 });

                if (enableSEH)
                {
                    writer.Write(new byte[] { 0x48, 0xB9 });
                    writer.Write(pExceptionTable.ToInt64());

                    writer.Write(new byte[] { 0xBA });
                    writer.Write(entryCount);

                    writer.Write(new byte[] { 0x49, 0xB8 });
                    writer.Write(moduleBase.ToInt64());

                    writer.Write(new byte[] { 0x48, 0xB8 });
                    writer.Write(pRtlAddFunctionTable.ToInt64());

                    writer.Write(new byte[] { 0xFF, 0xD0 });
                }

                writer.Write(new byte[] { 0x48, 0xBB });
                writer.Write(pFuncList.ToInt64());

                writer.Write(new byte[] { 0x41, 0xBC });
                writer.Write(functions.Count);

                writer.Write(new byte[] { 0x48, 0x8B, 0x03 });

                writer.Write(new byte[] { 0x48, 0xB9 });
                writer.Write(moduleBase.ToInt64());

                writer.Write(new byte[] { 0xBA, 0x01, 0x00, 0x00, 0x00 });

                writer.Write(new byte[] { 0x45, 0x31, 0xC0 });

                writer.Write(new byte[] { 0xFF, 0xD0 });

                writer.Write(new byte[] { 0x48, 0x83, 0xC3, 0x08 });
                writer.Write(new byte[] { 0x41, 0xFF, 0xCC });
                writer.Write(new byte[] { 0x75, 0xE0 });

                writer.Write(new byte[] { 0x48, 0x83, 0xC4, 0x28 });
                writer.Write(new byte[] { 0xC3 });

                byte[] shellcode = ms.ToArray();
                WriteProcessMemory(hProcess, pShellcode, shellcode, shellcode.Length, out _);
            }

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pShellcode, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero) return "CreateRemoteThread failed";
            
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            
            VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pFuncList, 0, MEM_RELEASE);
            
            return null;
        }

        static uint RvaToOffset(uint rva, ushort numberOfSections, IntPtr pSectionHeader)
        {
            for (int i = 0; i < numberOfSections; i++)
            {
                IMAGE_SECTION_HEADER section = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(pSectionHeader + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER))));
                if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
                {
                    return section.PointerToRawData + (rva - section.VirtualAddress);
                }
            }
            return 0;
        }

        static IntPtr GetRemoteModuleHandle(Process target, string moduleName)
        {
            foreach (ProcessModule module in target.Modules)
            {
                if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    return module.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        static void LoadRemoteLibrary(IntPtr hProcess, string moduleName)
        {
            IntPtr pLoadLibrary = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (pLoadLibrary == IntPtr.Zero) return;

            IntPtr pModuleName = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)moduleName.Length + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            WriteProcessMemory(hProcess, pModuleName, Encoding.ASCII.GetBytes(moduleName + "\0"), moduleName.Length + 1, out _);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, pLoadLibrary, pModuleName, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero) return;

            WaitForSingleObject(hThread, 5000);
        }
    }
}
