using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using PeNet;
using Reloaded.Injector.Exceptions;
using Reloaded.Injector.Interop;
using Reloaded.Injector.Interop.Structures;
using Reloaded.Memory.Buffers;
using Reloaded.Memory.Sources;
using Reloaded.Memory.Utilities;
using static Reloaded.Injector.Kernel32.Kernel32;

namespace Reloaded.Injector
{
    /// <summary>
    /// Builds the shellcode inside a target process which can be used to
    /// call LoadLibrary and GetProcAddress inside a remote process.
    /// </summary>
    internal class Shellcode : IDisposable
    {
        /* Setup/Build Shellcode */
        public  long        Kernel32Handle { get; } /* Address of Kernel32 in remote process. */
        private uint        _loadLibraryWOffset;    /* Address of LoadLibraryW in remote process. */
        private uint        _getProcAddressOffset;  /* Address of GetProcAddress in remote process. */
        private MachineType _machineType;           /* Is remote process 64 or 32bit? */

        /* Temp Helpers */
        private Assembler.Assembler _assembler;     /* Provides JIT Assembly of x86/x64 mnemonics.        */
        private PrivateMemoryBuffer _privateBuffer; /* Provides us with somewhere to write our shellcode. */

        /* Parm Helpers */
        private ExternalMemory      _memory;        /* Provides access to other process' memory. */
        private CircularBuffer      _circularBuffer;/* For passing in our parameters to shellcode.        */
        private Process             _targetProcess; /* The process we will be calling functions in.       */

        /* Final products. */ /* stdcall for x86, Microsoft for x64 */
        private long _loadLibraryWShellPtr;   /* Pointer to shellcode to execute LoadLibraryW.   */
        private long _getProcAddressShellPtr; /* Pointer to shellcode to execute GetProcAddress. */

        private long _loadLibraryWReturnValuePtr;   /* Address of LoadLibraryW's return value. */
        private long _getProcAddressReturnValuePtr; /* Address of GetProcAddress' return value. */

        /// <summary>
        /// Builds the shellcode necessary to successfully call LoadLibraryW and GetProcAddress
        /// inside the address space of another executable.
        /// </summary>
        /// <param name="targetProcess">Process inside which to execute.</param>
        public Shellcode(Process targetProcess)
        {
            Safety.WaitForModuleInitialization(targetProcess);

            _privateBuffer  = new MemoryBufferHelper(targetProcess).CreatePrivateMemoryBuffer(4096);
            _assembler      = new Assembler.Assembler();
            _memory         = new ExternalMemory(targetProcess);
            _circularBuffer = new CircularBuffer(4096, _memory);
            _targetProcess  = targetProcess;

            // Get arch of target process. 
            PeFile targetPeFile = new PeFile(targetProcess.Modules[0].FileName);
            _machineType        = (MachineType) targetPeFile.ImageNtHeaders.FileHeader.Machine;

            // Get Kernel32 load address in target.
            Module kernel32Module = GetKernel32InRemoteProcess(targetProcess);
            Kernel32Handle          = (long) kernel32Module.BaseAddress;

            // We need to change the module path if 32bit process; because the given path is not true,
            // it is being actively redirected by Windows on Windows 64 (WoW64)
            if (_machineType == MachineType.I386)
            {
                StringBuilder builder = new StringBuilder(256);
                GetSystemWow64Directory(builder, (uint)builder.Capacity);
                kernel32Module.ModulePath = builder.ToString() + "\\" + Path.GetFileName(kernel32Module.ModulePath);
            }
            
            // Parse Kernel32 loaded by target and get address of LoadLibrary & GetProcAddress.
            PeFile kernel32PeFile = new PeFile(kernel32Module.ModulePath);
            var exportedFunctions = kernel32PeFile.ExportedFunctions;

            _loadLibraryWOffset   = GetExportedFunctionOffset(exportedFunctions, "LoadLibraryW");
            _getProcAddressOffset = GetExportedFunctionOffset(exportedFunctions, "GetProcAddress");

            if (_loadLibraryWOffset == 0 || _getProcAddressOffset == 0)
                throw new ShellCodeGeneratorException("Failed to find GetProcAddress or LoadLibraryW methods in target process' Kernel32.");

            if (_machineType == MachineType.AMD64)
            {
                BuildLoadLibraryW64();
                BuildGetProcAddress64();
            }
            else
            {
                BuildLoadLibraryW86();
                BuildGetProcAddress86();
            }

            _assembler.Dispose();
            _assembler    = null;
        }

        /* Call Shellcode */

        public long GetProcAddress(long hModule, string functionName)
        {
            var getProcAddressParams = new GetProcAddressParams(hModule, WriteNullTerminatedASCIIString(functionName));
            long lpParameter         = (long)_circularBuffer.Add(ref getProcAddressParams);
            IntPtr threadHandle      = CreateRemoteThread(_targetProcess.Handle, IntPtr.Zero, UIntPtr.Zero, (IntPtr)_getProcAddressShellPtr, (IntPtr)lpParameter, CREATE_THREAD_FLAGS.RUN_IMMEDIATELY, out uint threadId);

            WaitForSingleObject(threadHandle, uint.MaxValue);

            _memory.Read((IntPtr) _getProcAddressReturnValuePtr, out long value);
            return value;
        }

        public long LoadLibraryW(string modulePath)
        {
            long lpParameter = WriteNullTerminatedUnicodeString(modulePath);
            IntPtr threadHandle = CreateRemoteThread(_targetProcess.Handle, IntPtr.Zero, UIntPtr.Zero, (IntPtr)_loadLibraryWShellPtr, (IntPtr)lpParameter, CREATE_THREAD_FLAGS.RUN_IMMEDIATELY, out uint threadId);

            WaitForSingleObject(threadHandle, uint.MaxValue);

            _memory.Read((IntPtr) _loadLibraryWReturnValuePtr, out long value);
            return value;
        }

        /* Build Shellcode */

        private void BuildGetProcAddress86()
        {
            // GetProcAddress(long hModule, char* lpProcName)
            // lpParameter: Address of first struct member.
            // Using stdcall calling convention.
            long getProcAddressAddress = Kernel32Handle + _getProcAddressOffset;
            IntPtr getProcAddressPtr   = _privateBuffer.Add(ref getProcAddressAddress);

            long dummy                    = 0;
            _getProcAddressReturnValuePtr = (long)_privateBuffer.Add(ref dummy);

            string[] getProcAddress =
            {
               $"use32",
                "mov eax, dword [esp + 4]", // CreateRemoteThread lpParameter
                "push dword [eax + 8]",     // lpProcName
                "push dword [eax + 0]",     // hModule
               $"call dword [dword 0x{getProcAddressPtr.ToString("X")}]",
               $"mov dword [dword 0x{_getProcAddressReturnValuePtr.ToString("X")}], eax",
                "ret 4"                     // Restore stack ptr. (Callee cleanup)
            };


            byte[] bytes = _assembler.Assemble(getProcAddress);
            _getProcAddressShellPtr = (long)_privateBuffer.Add(bytes);
        }

        private void BuildGetProcAddress64()
        {
            // GetProcAddress(long hModule, char* lpProcName)
            // lpParameter: Address of first struct member.
            // Using Microsoft X64 calling convention.
            long getProcAddressAddress = Kernel32Handle + _getProcAddressOffset;
            IntPtr getProcAddressPtr = _privateBuffer.Add(ref getProcAddressAddress);

            long dummy = 0;
            _getProcAddressReturnValuePtr = (long)_privateBuffer.Add(ref dummy);

            string[] getProcAddress =
            {
                $"use64",
                                                      // CreateRemoteThread lpParameter @ ECX
                "sub rsp, 40",                        // Re-align stack to 16 byte boundary +32 shadow space
                "mov rdx, qword [qword rcx + 8]",     // lpProcName
                "mov rcx, qword [qword rcx + 0]",     // hModule
                $"call qword [qword 0x{getProcAddressPtr.ToString("X")}]",
                $"mov qword [qword 0x{_getProcAddressReturnValuePtr.ToString("X")}], rax",
                "add rsp, 40",                        // Re-align stack to 16 byte boundary + shadow space.
                "ret"                     // Restore stack ptr. (Callee cleanup)
            };


            byte[] bytes = _assembler.Assemble(getProcAddress);
            _getProcAddressShellPtr = (long)_privateBuffer.Add(bytes);
        }

        private void BuildLoadLibraryW86()
        {
            // Using stdcall calling convention.
            long loadLibraryAddress = Kernel32Handle + _loadLibraryWOffset;
            IntPtr loadLibraryPtr   = _privateBuffer.Add(ref loadLibraryAddress);

            long dummy = 0;
            _loadLibraryWReturnValuePtr = (long)_privateBuffer.Add(ref dummy);

            string[] loadLibraryW   =
            {
               $"use32",
                "push dword [ESP + 4]",     // CreateRemoteThread lpParameter
               $"call dword [dword 0x{loadLibraryPtr.ToString("X")}]",
               $"mov dword [dword 0x{_loadLibraryWReturnValuePtr.ToString("X")}], eax",
                "ret 4"                     // Restore stack ptr. (Callee cleanup)
            };

            
            byte[] bytes        = _assembler.Assemble(loadLibraryW);
            _loadLibraryWShellPtr = (long)_privateBuffer.Add(bytes);
        }


        private void BuildLoadLibraryW64()
        {
            // Using Microsoft X64 calling convention.
            long loadLibraryAddress   = Kernel32Handle + _loadLibraryWOffset;
            IntPtr loadLibraryPtr     = _privateBuffer.Add(ref loadLibraryAddress);
            
            long dummy = 0;
            _loadLibraryWReturnValuePtr = (long)_privateBuffer.Add(ref dummy);

            string[] loadLibraryW =
            {
                $"use64",
                "sub rsp, 40",                                // Re-align stack to 16 byte boundary + shadow space.
                $"call qword [qword 0x{loadLibraryPtr.ToString("X")}]", // CreateRemoteThread lpParameter with string already in ECX.
                $"mov qword [qword 0x{_loadLibraryWReturnValuePtr.ToString("X")}], rax",
                "add rsp, 40",                                // Re-align stack to 16 byte boundary + shadow space.
                "ret"                                         // Restore stack ptr. (Callee cleanup)
            };

            byte[] bytes = _assembler.Assemble(loadLibraryW);
            _loadLibraryWShellPtr = (long)_privateBuffer.Add(bytes);
        }

        /* Utility functions. */

        private uint GetExportedFunctionOffset(ExportFunction[] exportFunctions, string functionName) // Case sensitive.
        {
            foreach (var function in exportFunctions)
                if (function.Name == functionName)
                    return function.Address;

            return 0;
        }

        private long WriteNullTerminatedASCIIString(string libraryPath)
        {
            byte[] libraryNameBytes = Encoding.ASCII.GetBytes(libraryPath + '\0');
            return (long)_circularBuffer.Add(libraryNameBytes);
        }

        private long WriteNullTerminatedUnicodeString(string libraryPath)
        {
            byte[] libraryNameBytes = Encoding.Unicode.GetBytes(libraryPath + '\0');
            return (long)_circularBuffer.Add(libraryNameBytes);
        }

        /* One off construction functions. */

        private Module GetKernel32InRemoteProcess(Process process)
        {
            foreach (Module module in ModuleCollector.CollectModules(process))
                if (Path.GetFileName(module.ModulePath).Equals("KERNEL32.DLL", StringComparison.InvariantCultureIgnoreCase))
                    return module;

            throw new ShellCodeGeneratorException("Failed to find Kernel32 in target process' modules.");
        }

        /* Other types. */

        [StructLayout(LayoutKind.Sequential)]
        private struct GetProcAddressParams
        {
            public long HModule     { get; set; }
            public long LPProcName  { get; set; }

            public GetProcAddressParams(long hModule, long lPProcName) : this()
            {
                HModule = hModule;
                LPProcName = lPProcName;
            }
        }

        private enum MachineType
        {
            AMD64 = 34404,
            I386 = 332,
            IA64 = 512
        }

        /// <summary/>
        public void Dispose()
        {
            _assembler?.Dispose();
            _privateBuffer?.Dispose();
            _circularBuffer?.Dispose();
        }
    }
}
