using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Reloaded.Injector.Exceptions;
using Reloaded.Injector.Interop;
using Reloaded.Memory;
using Reloaded.Memory.Structs;
using Reloaded.Memory.Utilities;
using static Reloaded.Injector.Kernel32.Kernel32;

namespace Reloaded.Injector
{
    /// <summary>
    /// Provides a means by which a target DLLs may be injected into an individual process.
    /// If the target process is running the administrator, the injector should also be
    /// ran as administrator.
    /// </summary>
    public class Injector : IDisposable
    {
        /// <summary>
        /// True when the target process to inject is no longer running, else false.
        /// </summary>
        public bool HasExited => _process.HasExited;

        /// <summary>
        /// Provides access to the raw GetProcAddress and LoadLibrary calls.
        /// </summary>
        public Shellcode ShellCode { get; private set; }    /* Call GetProcAddress and LoadLibraryW in remote process. */

        private PrivateMemoryBufferCompat _circularBuffer;             /* Used for calling foreign functions. */
        //private MemoryAllocation _circularBufferSource;

        private Process _process;                           /* Process to DLL Inject into. */

        /// <summary>
        /// Initializes the DLL Injector.
        /// </summary>
        /// <param name="process">The process to inject DLLs into.</param>
        public Injector(Process process)
        {
            // Initiate target process.
            _process = process;
            _procMemory = new ExternalMemory(process);
            _circularBuffer = new(process, Shellcode.CircularBufferSize);
            ShellCode = new Shellcode(process);
        }
        private ExternalMemory _procMemory;
        ~Injector()
        {
            Dispose();
        }

        /// <inheritdoc/>
        public void Dispose()
        {

            ShellCode?.Dispose();
            _circularBuffer?.Dispose();
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Injects a DLL into the target process.
        /// </summary>
        /// <param name="modulePath">The absolute path to your DLL to be injected.</param>
        /// <param name="msTimeout">Miliseconds to potentially wait for things like module loading on a new proc.</param>
        /// <remarks>This function executes LoadLibraryW inside the remote process.</remarks>
        /// <exception cref="DllInjectorException">The target process is not running.</exception>
        /// <returns>The address/handle of the loaded in library inside the target process. Zero if the operation failed.</returns>
        public long Inject(string modulePath, int msTimeout=3000)
        {
            // Error checking.
            AssertProcessNotRunning();

            var moduleHandle = IsAbsolutePath(modulePath) ? GetModuleHandleFromPath(modulePath, msTimeout) : GetModuleHandleFromName(modulePath, msTimeout);
            if (moduleHandle != IntPtr.Zero)
                return (long)moduleHandle;

            long address = ShellCode.LoadLibraryW(modulePath);
            
            return address;
        }

        /// <summary>
        /// Retrieves the address of a function in a module loaded inside the target process.
        /// </summary>
        /// <param name="module">The name or full path of the module.</param>
        /// <param name="functionToExecute">The function of that module to be executed.</param>
        /// <remarks>This function remotely executes GetProcAddress inside the given process.</remarks>
        /// <exception cref="DllInjectorException">The DLL is not loaded in the target process.</exception>
        public long GetFunctionAddress(string module, string functionToExecute)
        {
            var moduleHandle = IsAbsolutePath(module) ? GetModuleHandleFromPath(module) : GetModuleHandleFromName(module);
            if (moduleHandle == IntPtr.Zero)
                throw new DllInjectorException("Module not found in target process.");

            return ShellCode.GetProcAddress((long)moduleHandle, functionToExecute);
        }

        /// <summary>
        /// Calls a function in a remote process using CreateRemoteThread.
        /// </summary>
        /// <typeparam name="TStruct">A structure type to pass as a parameter to the target function.</typeparam>
        /// <param name="module">The name or full path of the module to execute a function.</param>
        /// <param name="functionToExecute">The function of that module to be executed.</param>
        /// <param name="parameter">
        ///     A parameter to pass onto the function. It is written into memory and a pointer to it
        ///     is passed to the target function.
        /// </param>
        /// <param name="marshalParameter">
        ///     Set to true to enable marshalling of the parameter being passed into the receiving application.
        /// </param>
        /// <remarks>
        ///     Passing of only 1 parameter is supported. If you want to pass multiple parameters, pass a struct
        ///     This function passes a pointer to your parameter to the target function.
        ///     A parameter must be passed and the target method must expect it. This is a limitation of CreateRemoteThread.
        /// </remarks>
        /// <returns>A 32bit truncated exit code/return value. CreateRemoteThread does not support 64bit returns.</returns>
        public unsafe int CallFunction<TStruct>(string module, string functionToExecute, TStruct parameter = default) where TStruct : struct
        {

            var parameterPtr = _circularBuffer.Add(ref parameter);
            return CallFunctionPtr(module, functionToExecute, (UInt64)parameterPtr);
        }
        public int CallFunction<TStruct>(string module, string functionToExecute, TStruct parameter = default, bool marshalParameter = false) where TStruct : unmanaged
        {
            var parameterPtr = _circularBuffer.Add(ref parameter, marshalParameter);
            return CallFunctionPtr(module, functionToExecute, (UInt64)parameterPtr);
        }

        /// <summary>
        /// Calls a function in a remote process using CreateRemoteThread.
        /// </summary>
        /// <param name="module">The name or full path of the module to execute a function.</param>
        /// <param name="functionToExecute">The function of that module to be executed.</param>
        /// <param name="parameterPtr">Raw value/pointer to parameter to pass to the target function.</param>
        /// <returns>A 32bit truncated exit code/return value. CreateRemoteThread does not support 64bit returns.</returns>
        public int CallFunctionPtr(string module, string functionToExecute, UInt64 parameterPtr)
        {
            long methodAddress = GetFunctionAddress(module, functionToExecute);
            return CallRemoteFunction(_process.Handle, (IntPtr)methodAddress, (IntPtr) parameterPtr);
        }

        /// <summary>
        /// Unloads a library with a specified path from the target process.
        /// </summary>
        /// <returns>False if the operation failed, else true.</returns>
        public bool Eject(string module)
        {
            // Get handle of module.
            var moduleHandle = IsAbsolutePath(module) ? GetModuleHandleFromPath(module) : GetModuleHandleFromName(module);
            if (moduleHandle == IntPtr.Zero)
                return false;

            long methodAddress  = ShellCode.GetProcAddress(ShellCode.Kernel32Handle, "FreeLibrary");
            
            int result = CallRemoteFunction(_process.Handle, (IntPtr)methodAddress, moduleHandle);
            return Convert.ToBoolean(result);
        }

        /// <summary>
        /// Retrieves the handle (memory address) of where the module with a specified file path is loaded in the target process.
        /// </summary>
        /// <param name="modulePath">The absolute path of the module (including extension).</param>
        /// <returns>0 if the operation fails, else an address.</returns>
        public IntPtr GetModuleHandleFromPath(string modulePath, int msTimeout=3000)
        {
            string fullPath = Path.GetFullPath(modulePath);
            foreach (var module in Safety.TryGetModules(_process, msTimeout))
            {
                if (Path.GetFullPath(module.ModulePath) == fullPath)
                    return module.BaseAddress;
            }

            return IntPtr.Zero;
        }

        /// <summary>
        /// Retrieves the handle (memory address) of where the module with a specified name is loaded in the target process.
        /// </summary>
        /// <param name="moduleName">The name of the module (including extension).</param>
        /// <returns>0 if the operation fails, else an address.</returns>
        public IntPtr GetModuleHandleFromName(string moduleName, int msTimeout=3000)
        {
            foreach (var module in Safety.TryGetModules(_process, msTimeout))
            {
                if (Path.GetFileName(module.ModulePath) == moduleName)
                    return module.BaseAddress;
            }

            return IntPtr.Zero;
        }

        /* Core Functionality */
        
        private int CallRemoteFunction(IntPtr processHandle, IntPtr methodAddress, IntPtr parameterAddress)
        {
            // Create and initialize a thread at our address and parameter address.
            IntPtr hThread = CreateRemoteThread(processHandle, IntPtr.Zero, UIntPtr.Zero, methodAddress, parameterAddress, 0, out uint threadId);

            WaitForSingleObject(hThread, uint.MaxValue);
            GetExitCodeThread(hThread, out uint exitCode);
            
            return (int)exitCode;
        }
        
        /* Utilities */

        private bool IsAbsolutePath(string path)
        {
            return Path.IsPathRooted(path);
        }

        private void AssertProcessNotRunning()
        {
            if (HasExited)
                throw new DllInjectorException("The target process to inject to has exited, it is no longer running.");
        }

    }
}
