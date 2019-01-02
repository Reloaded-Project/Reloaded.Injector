using System;
using System.Diagnostics;

namespace Reloaded.Injector.Tests.X64
{
    public class HelloWorldFixture : IDisposable
    {
        private const string InjectModule32 = "Reloaded.Injector.Tests.Dll32.dll";
        private const string InjectModule64 = "Reloaded.Injector.Tests.Dll64.dll";

        public Process  Target32    { get; set; }
        public Process  Target64    { get; set; }

        public Injector Injector32  { get; set; }
        public Injector Injector64  { get; set; }

        public HelloWorldFixture()
        {
            Target32 = Process.Start("HelloWorld32");
            Target64 = Process.Start("HelloWorld64");

            Injector32 = new Injector(Target32);
            Injector32.Inject(InjectModule32);

            Injector64 = new Injector(Target64);
            Injector64.Inject(InjectModule64);
        }

        public void Dispose()
        {
            // Order is important here.
            // If eject crashes the process, exception here throws and tests fail.
            Injector32.Eject(InjectModule32);
            Injector64.Eject(InjectModule64);

            Target32?.Kill();
            Target32?.Dispose();

            Target64?.Kill();
            Target64?.Dispose();
        }
    }
}
