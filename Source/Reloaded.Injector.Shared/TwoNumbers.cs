using System.Diagnostics.CodeAnalysis;

namespace Reloaded.Injector.Shared
{
    [ExcludeFromCodeCoverage]
    public struct TwoNumbers
    {
        public int A { get; private set; }
        public int B { get; private set; }

        public TwoNumbers(int a, int b) : this()
        {
            A = a;
            B = b;
        }
    }
}
