using System.Diagnostics.CodeAnalysis;
using Reloaded.Injector.Shared;

namespace Reloaded.Injector.Tests.Dll32
{
    [ExcludeFromCodeCoverage]
    public unsafe class Calculator
    {
        [DllExport]
        public static int Add(TwoNumbers* twoNumbers)
        {
            return twoNumbers->A + twoNumbers->B;
        }

        [DllExport]
        public static int Subtract(TwoNumbers* twoNumbers)
        {
            return twoNumbers->A - twoNumbers->B;
        }

        [DllExport]
        public static int Multiply(TwoNumbers* twoNumbers)
        {
            return twoNumbers->A * twoNumbers->B;
        }

        [DllExport]
        public static int Divide(TwoNumbers* twoNumbers)
        {
            return twoNumbers->A / twoNumbers->B;
        }
    }
}
