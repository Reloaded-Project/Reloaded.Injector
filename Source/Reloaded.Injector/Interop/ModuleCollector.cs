using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Reloaded.Injector.Exceptions;
using Reloaded.Injector.Interop.Structures;

namespace Reloaded.Injector.Interop;

internal static unsafe class ModuleCollector
{
    private static StringBuilder _modulePathBuilder = new StringBuilder(32767);

    /// <summary>
    /// Retrieves the path of the main module.
    /// </summary>
    public static string GetMainModulePath(Process process) => GetModulePath(process, IntPtr.Zero);

    /// <summary>
    /// Retrieves the path of a module with a given handle.
    /// </summary>
    public static string GetModulePath(Process process, IntPtr hModule)
    {
        _modulePathBuilder.Length = 0;
        int size = (int)GetModuleFileNameEx(process.Handle, hModule, _modulePathBuilder, (uint)_modulePathBuilder.Capacity);
        if (size == 0)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        
        return _modulePathBuilder.ToString();
    }

    /// <exception cref="DllInjectorException">Bytes to fill module list returned 0. The process is probably not yet initialized.</exception>
    public static List<Module> CollectModules(Process process)
    {
        List<Module> collectedModules = new List<Module>();
        IntPtr[] modulePointers       = new IntPtr[0];
        int numberOfModules;
        int bytesNeeded;

        // Determine number of modules.
        if (!EnumProcessModulesEx(process.Handle, modulePointers, 0, out bytesNeeded, (uint)ModuleFilter.ListModulesAll))
            return collectedModules;

        if (bytesNeeded == 0)
            throw new DllInjectorException("Bytes needed to dump module list returned 0. This means that either the process probably not yet fully initialized.");

        numberOfModules = bytesNeeded / IntPtr.Size;
        modulePointers  = new IntPtr[numberOfModules];

        // Collect modules from the process
        if (EnumProcessModulesEx(process.Handle, modulePointers, bytesNeeded, out bytesNeeded, (uint)ModuleFilter.ListModulesAll))
        {
            for (int x = 0; x < numberOfModules; x++)
            {
                ModuleInformation moduleInformation = new ModuleInformation();

                _modulePathBuilder.Length = 0;
                GetModuleFileNameEx(process.Handle, modulePointers[x], _modulePathBuilder, (uint)(_modulePathBuilder.Capacity));
                GetModuleInformation(process.Handle, modulePointers[x], out moduleInformation, (uint)sizeof(ModuleInformation));

                // Convert to a normalized module and add it to our list
                string modulePath = _modulePathBuilder.ToString();
                Module module = new Module(modulePath, moduleInformation.lpBaseOfDll, moduleInformation.SizeOfImage, moduleInformation.EntryPoint);
                collectedModules.Add(module);
            }
        }

        return collectedModules;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ModuleInformation
    {
        public IntPtr lpBaseOfDll;
        public uint   SizeOfImage;
        public IntPtr EntryPoint;
    }

    internal enum ModuleFilter
    {
        ListModulesDefault = 0x0,
        ListModules32Bit = 0x01,
        ListModules64Bit = 0x02,
        ListModulesAll = 0x03,
    }

    [DllImport("psapi.dll")]
    private static extern bool EnumProcessModulesEx(IntPtr hProcess, IntPtr[] lphModule, int cb, out int lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll")]
    private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, uint nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out ModuleInformation lpmodinfo, uint cb);
    
    // Win32 API declarations
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);
}