using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
// ReSharper disable InconsistentNaming

namespace Reloaded.Injector.Shared;

/// <summary>
/// Represents an individual process that started suspended.
/// </summary>
public class SuspendedProcess : IDisposable
{
    private PROCESS_INFORMATION _processInformation;

    public Process Process;
    
    public void Dispose()
    {
        CloseHandle(_processInformation.hProcess);
        TerminateProcess(_processInformation.hProcess, 0);
    }

    public void Unsuspend() => ResumeThread(_processInformation.hThread);

    public static SuspendedProcess Start(string path)
    {
        const int CREATE_SUSPENDED = 0x00000004;
        
        // Start the process in suspended mode
        STARTUPINFO startupInfo = new STARTUPINFO();
        PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
        if (!CreateProcessW(null, path, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref startupInfo, out processInfo))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        return new SuspendedProcess()
        {
            _processInformation = processInfo,
            Process = System.Diagnostics.Process.GetProcessById(processInfo.dwProcessId)
        };
    }

    // Win32 API declarations

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public readonly int cb;
        public readonly string lpReserved;
        public readonly string lpDesktop;
        public readonly string lpTitle;
        public readonly int dwX;
        public readonly int dwY;
        public readonly int dwXSize;
        public readonly int dwYSize;
        public readonly int dwXCountChars;
        public readonly int dwYCountChars;
        public readonly int dwFillAttribute;
        public readonly int dwFlags;
        public readonly short wShowWindow;
        public readonly short cbReserved2;
        public readonly IntPtr lpReserved2;
        public readonly IntPtr hStdInput;
        public readonly IntPtr hStdOutput;
        public readonly IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public readonly IntPtr hProcess;
        public readonly IntPtr hThread;
        public readonly int dwProcessId;
        public readonly int dwThreadId;
    }
    
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
}