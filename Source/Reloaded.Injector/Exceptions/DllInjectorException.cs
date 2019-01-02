#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace Reloaded.Injector.Exceptions
{
    [ExcludeFromCodeCoverage]
    public class DllInjectorException : Exception
    {
        /* For any other exceptions. */
        public DllInjectorException() { }
        public DllInjectorException(string message) : base(message) { }
        public DllInjectorException(string message, Exception innerException) : base(message, innerException) { }
        protected DllInjectorException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
