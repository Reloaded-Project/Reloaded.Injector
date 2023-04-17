using System;
using System.Diagnostics;
using Reloaded.Injector.Shared;

namespace Reloaded.Injector.Tests.X86;

public class HelloWorldFixture : IDisposable
{
    private const string InjectModule32 = "Reloaded.Injector.Tests.Dll32.dll";

    public SuspendedProcess Target32    { get; set; }
    public Injector Injector32 { get; set; }

    public HelloWorldFixture()
    {
        Target32 = SuspendedProcess.Start("HelloWorld32.exe");
        Injector32 = new Injector(Target32.Process);
        Injector32.Inject(InjectModule32);
    }

    public void Dispose()
    {
        // Order is important here.
        // If eject crashes the process, exception here throws and tests fail.
        Injector32.Eject(InjectModule32);
        Target32?.Dispose();
    }
}