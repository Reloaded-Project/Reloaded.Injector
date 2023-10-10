using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using PeNet;
using PeNet.Header.Pe;
using Reloaded.Injector.Exceptions;
using Reloaded.Injector.Interop.Structures;
using Reloaded.Memory;
using static Reloaded.Injector.Kernel32.Kernel32;

namespace Reloaded.Injector
{
    /// <summary>
    /// Builds the shellcode inside a target process which can be used to
    /// call LoadLibrary and GetProcAddress inside a remote process.
    /// </summary>
    public class Shellcode : IDisposable
    {
		public static nuint CircularBufferSize = 4096;
		public static nuint PrivateBufferSize = 4096;//orig did 4096
		public static bool AssemblyLargePtrFix = false;// THIS DOES NOT WORK but if the ptr to our memroy is too high the fasm call will fail so wil need to figure out a work around
		internal const nuint minimumAddress = 65536u;
		internal const int retryCount = 3;
        /* Setup/Build Shellcode */
        public  long        Kernel32Handle      { get; }                /* Address of Kernel32 in remote process. */
        public  long        LoadLibraryAddress  { get; private set; }   /* Address of LoadLibrary function. */
        public  long        GetProcAddressAddress { get; private set; } /* Address of GetProcAddress function. */

        private uint        _loadLibraryWOffset;    /* Address of LoadLibraryW in remote process. */
        private uint        _getProcAddressOffset;  /* Address of GetProcAddress in remote process. */
        private MachineType _machineType;           /* Is remote process 64 or 32bit? */

        /* Temp Helpers */
        private Assembler.Assembler _assembler;     /* Provides JIT Assembly of x86/x64 mnemonics.        */
        private PrivateMemoryBufferCompat _privateBuffer; /* Provides us with somewhere to write our shellcode. */

        /* Perm Helpers */
        private ExternalMemory      _memory;        /* Provides access to other process' memory.          */
		private PrivateMemoryBufferCompat _circularBuffer; /* the actual circular buffer no longer works with external process memory */

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

			_privateBuffer = new PrivateMemoryBufferCompat(targetProcess,PrivateBufferSize, true); 
            _assembler      = new Assembler.Assembler();
            _memory         = new ExternalMemory(targetProcess);
            _circularBuffer = new (targetProcess, CircularBufferSize);
            _targetProcess  = targetProcess;

            // Get arch of target process. 
            PeFile targetPeFile = new PeFile(targetProcess.Modules[0].FileName);
            _machineType        = (MachineType) targetPeFile.ImageNtHeaders.FileHeader.Machine;

            // Get Kernel32 load address in target.
            Module kernel32Module   = GetKernel32InRemoteProcess(targetProcess);
            Kernel32Handle          = (long) kernel32Module.BaseAddress;

            // We need to change the module path if 32bit process; because the given path is not true,
            // it is being actively redirected by Windows on Windows 64 (WoW64)
            if (_machineType == MachineType.I386 && Environment.Is64BitOperatingSystem)
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

        ~Shellcode()
        {
            Dispose();
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _assembler?.Dispose();
            _privateBuffer?.Dispose();
            _circularBuffer?.Dispose();
            GC.SuppressFinalize(this);
        }

        /* Call Shellcode */

        public long GetProcAddress(long hModule, string functionName)
        {
            var getProcAddressParams = new GetProcAddressParams(hModule, WriteNullTerminatedASCIIString(functionName));
            long lpParameter         = (long)_circularBuffer.Add(ref getProcAddressParams);
            IntPtr threadHandle      = CreateRemoteThread(_targetProcess.Handle, IntPtr.Zero, UIntPtr.Zero, (IntPtr)_getProcAddressShellPtr, (IntPtr)lpParameter, CREATE_THREAD_FLAGS.RUN_IMMEDIATELY, out uint threadId);

            WaitForSingleObject(threadHandle, uint.MaxValue);

            _memory.Read((UIntPtr)_getProcAddressReturnValuePtr, out long value);
            return value;
        }

        public long LoadLibraryW(string modulePath)
        {
            long lpParameter = WriteNullTerminatedUnicodeString(modulePath);
            IntPtr threadHandle = CreateRemoteThread(_targetProcess.Handle, IntPtr.Zero, UIntPtr.Zero, (IntPtr)_loadLibraryWShellPtr, (IntPtr)lpParameter, CREATE_THREAD_FLAGS.RUN_IMMEDIATELY, out uint threadId);

            WaitForSingleObject(threadHandle, uint.MaxValue);

            _memory.Read((UIntPtr)_loadLibraryWReturnValuePtr, out long value);
            return value;
        }

        /* Build Shellcode */

        private void BuildGetProcAddress86()
        {
            // GetProcAddress(long hModule, char* lpProcName)
            // lpParameter: Address of first struct member.
            // Using stdcall calling convention.
            long getProcAddressAddress  = Kernel32Handle + _getProcAddressOffset;
            GetProcAddressAddress       = getProcAddressAddress;
            var getProcAddressPtr       = _privateBuffer.Add(ref getProcAddressAddress);

            long dummy                    = 0;
            _getProcAddressReturnValuePtr = (long)_privateBuffer.Add(ref dummy);

            string[] getProcAddress =
            {
               $"use32",
                "mov eax, dword [esp + 4]", // CreateRemoteThread lpParameter
                "push dword [eax + 8]",     // lpProcName
                "push dword [eax + 0]",     // hModule
               $"call dword [dword {getProcAddressPtr}]",
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
            long getProcAddressAddress  = Kernel32Handle + _getProcAddressOffset;
            GetProcAddressAddress       = getProcAddressAddress;
            var getProcAddressPtr       = _privateBuffer.Add(ref getProcAddressAddress);

            long dummy = 0;
            _getProcAddressReturnValuePtr = (long)_privateBuffer.Add(ref dummy);

            string[] getProcAddress =
            {
                $"use64",
                                                      // CreateRemoteThread lpParameter @ ECX
                "sub rsp, 40",                        // Re-align stack to 16 byte boundary +32 shadow space
                "mov rdx, qword [qword rcx + 8]",     // lpProcName
                "mov rcx, qword [qword rcx + 0]",     // hModule
                AssemblyLargePtrFix ? $"mov qword [qword {getProcAddressPtr}], rax": $"call qword [qword {getProcAddressPtr}]",// CreateRemoteThread lpParameter with string already in ECX.
				
				AssemblyLargePtrFix ? $"call rax" : "",

                $"mov qword [qword 0x{_getProcAddressReturnValuePtr.ToString("X")}], rax",
                "add rsp, 40",                        // Re-align stack to 16 byte boundary + shadow space.
                "ret"                     // Restore stack ptr. (Callee cleanup)
            };

			var bytes = GetASM("BuildGetProcAddress64", getProcAddress);
            _getProcAddressShellPtr = (long)_privateBuffer.Add(bytes);
        }
		private byte[] GetASM(String for_what, params string[] lines) {
            byte[] bytes = _assembler.Assemble(lines);
			return bytes;
		}
        private void BuildLoadLibraryW86()
        {
            // Using stdcall calling convention.
            long loadLibraryAddress = Kernel32Handle + _loadLibraryWOffset;
            LoadLibraryAddress      = loadLibraryAddress;
            var loadLibraryPtr      = _privateBuffer.Add(ref loadLibraryAddress);

            long dummy = 0;
            _loadLibraryWReturnValuePtr = (long)_privateBuffer.Add(ref dummy);

            string[] loadLibraryW   =
            {
               $"use32",
                "push dword [ESP + 4]",     // CreateRemoteThread lpParameter
               $"call dword [dword {loadLibraryPtr}]",
               $"mov dword [dword 0x{_loadLibraryWReturnValuePtr.ToString("X")}], eax",
                "ret 4"                     // Restore stack ptr. (Callee cleanup)
            };

            
            byte[] bytes        = _assembler.Assemble(loadLibraryW);
            _loadLibraryWShellPtr = (long)_privateBuffer.Add(bytes);
        }


        private void BuildLoadLibraryW64()
        {
            // Using Microsoft X64 calling convention.
            long loadLibraryAddress     = Kernel32Handle + _loadLibraryWOffset;
            LoadLibraryAddress          = loadLibraryAddress;
            var loadLibraryPtr          = _privateBuffer.Add(ref loadLibraryAddress);
            
            long dummy = 0;
            _loadLibraryWReturnValuePtr = (long)_privateBuffer.Add(ref dummy);

            string[] loadLibraryW =
            {
                $"use64",
                "sub rsp, 40",                                // Re-align stack to 16 byte boundary + shadow space.
                AssemblyLargePtrFix ? $"mov qword [qword {loadLibraryPtr}], rax" : $"call qword [qword {loadLibraryPtr}]", // CreateRemoteThread lpParameter with string already in ECX.  //seems to throw an error of value out of range for high bit addresses
				AssemblyLargePtrFix ? $"call rax" : "", // CreateRemoteThread lpParameter with string already in ECX.

                $"mov qword [qword 0x{_loadLibraryWReturnValuePtr.ToString("X")}], rax",
                "add rsp, 40",                                // Re-align stack to 16 byte boundary + shadow space.
                "ret"                                         // Restore stack ptr. (Callee cleanup)
            };
			var bytes = GetASM("BuildLoadLibraryW64", loadLibraryW);
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
            var adr =  _circularBuffer.Add(libraryNameBytes);
			return (long)adr;
        }

        /* One off construction functions. */

        private Module GetKernel32InRemoteProcess(Process process)
        {
            foreach (Module module in Safety.TryGetModules(process))
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
    }
}
