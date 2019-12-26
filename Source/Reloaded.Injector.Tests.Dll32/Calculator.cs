using System.Diagnostics.CodeAnalysis;
using NXPorts.Attributes;
using Reloaded.Injector.Shared;

namespace Reloaded.Injector.Tests.Dll32
{
    [ExcludeFromCodeCoverage]
    public unsafe class Calculator
    {
        [Export]
        public static int Add(TwoNumbers* twoNumbers)
        {
            return twoNumbers->A + twoNumbers->B;
        }

        [Export]
        public static int Subtract(TwoNumbers* twoNumbers)
        {
            return twoNumbers->A - twoNumbers->B;
        }

        [Export]
        public static int Multiply(TwoNumbers* twoNumbers)
        {
            return twoNumbers->A * twoNumbers->B;
        }

        [Export]
        public static int Divide(TwoNumbers* twoNumbers)
        {
            return twoNumbers->A / twoNumbers->B;
        }
    }
}
