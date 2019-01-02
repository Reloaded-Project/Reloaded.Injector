using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace Reloaded.Injector.Exceptions
{
    [ExcludeFromCodeCoverage]
    class ShellCodeGeneratorException : Exception
    {
        public ShellCodeGeneratorException() { }
        public ShellCodeGeneratorException(string message) : base(message) { }
        public ShellCodeGeneratorException(string message, Exception innerException) : base(message, innerException) { }
        protected ShellCodeGeneratorException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
