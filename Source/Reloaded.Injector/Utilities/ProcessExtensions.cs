using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Reloaded.Injector.Utilities;

/// <summary>
/// Extensions that run over the Process class.
/// </summary>
public static class ProcessExtensions
{
    /// <summary>
    /// Checks if a process is 64-bit or not.
    /// </summary>
    /// <param name="process">The process to check.</param>
    /// <returns>The process in question.</returns>
    public static bool Is64Bit(this Process process)
    {
        if (IntPtr.Size == 4)
            return false;

        return !(IsWow64Process(process.Handle, out bool isGame32Bit) && isGame32Bit);
    }
    
    // Win32 API declarations
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool IsWow64Process(IntPtr hProcess, out bool isProcess64);
}