using System;
using System.IO;

namespace Reloaded.Injector.Interop.Structures
{
    internal class Module
    {
        public string ModulePath    { get; set; }
        public IntPtr BaseAddress   { get; set; }
        public IntPtr EntryPoint    { get; set; }
        public uint Size            { get; set; }

        public Module(string modulePath, IntPtr baseAddress, uint size, IntPtr entryPoint)
        {
            this.ModulePath = modulePath;
            this.BaseAddress = baseAddress;
            this.Size = size;
            this.EntryPoint = entryPoint;
        }

        public override string ToString() => Path.GetFileName(ModulePath);
    }
}
