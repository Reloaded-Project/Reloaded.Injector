using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Reloaded.Injector.Kernel32
{
    internal static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, CREATE_THREAD_FLAGS dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint GetSystemWow64Directory(StringBuilder lpBuffer, uint uSize);

        [Flags]
        public enum CREATE_THREAD_FLAGS
        {
            RUN_IMMEDIATELY = 0,
            CREATE_SUSPENDED = 4,
            STACK_SIZE_PARAM_IS_A_RESERVATION = 65536
        }
    }
}
