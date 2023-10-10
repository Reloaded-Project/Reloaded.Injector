#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Reloaded.Memory;
using Reloaded.Memory.Buffers;
using Reloaded.Memory.Buffers.Structs;
using Reloaded.Memory.Structs;
using Reloaded.Memory.Utilities;
//using static Reloaded.Injector.Kernel32.Kernel32;
using K32 = Reloaded.Memory.Native.Windows.Kernel32;

namespace Reloaded.Injector {
	internal static class CompatUtils { //for back compat with other reload modules

		public static unsafe long AddBytes(this CircularBuffer buffer, Span<byte> bytes) {
			fixed (byte* ptr = bytes) {
				return (long)buffer.Add(ptr, (uint)bytes.Length);
			}

		}
	}

	public class PrivateMemoryBufferCompat : IDisposable {

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public MemoryAllocation Allocate(Process proc, nuint length, nuint baseStartAddy = 0) {

			nuint num = K32.VirtualAllocEx(proc.Handle, baseStartAddy, length, K32.MEM_ALLOCATION_TYPE.MEM_COMMIT | K32.MEM_ALLOCATION_TYPE.MEM_RESERVE, K32.MEM_PROTECTION.PAGE_EXECUTE_READWRITE);
			if (num != 0) {
				return new MemoryAllocation(num, length);
			}
			throw new Exception();

		}



        public PrivateMemoryBufferCompat(Process proc, nuint size, bool isPrivateAlloc = false) {
			IsPrivateAlloc = isPrivateAlloc;
			memory = new ExternalMemory(proc);
			if (!IsPrivateAlloc)
				alloc = memory.Allocate(size);
			else
				palloc = Buffers.AllocatePrivateMemory(new Reloaded.Memory.Buffers.Structs.Params.BufferAllocatorSettings { TargetProcess = proc, MinAddress = Shellcode.minimumAddress, MaxAddress = (nuint)UInt64.MaxValue, Size = (uint)size, RetryCount = Shellcode.retryCount });
		}
        private bool IsPrivateAlloc;
		public nuint BaseAddress => IsPrivateAlloc ? palloc.BaseAddress : alloc.Address;
		public nuint AllocSize => IsPrivateAlloc ? palloc.Size : alloc.Length;
		private MemoryAllocation alloc;
		private PrivateAllocation palloc;
		//private PrivateAllocation memory;
		private ExternalMemory memory;
		private bool disposedValue;
		private nuint nextFreeBlockOffset = 0;

		protected virtual void Dispose(bool disposing) {
			if (!disposedValue) {
				if (disposing) {

				}
				if (IsPrivateAlloc)
					palloc.Dispose();
				else
					memory.Free(alloc);

				disposedValue = true;
			}
		}

		private object writeLock = new();
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static nuint GetSize<T>(bool marshalElement) {
			if (!marshalElement)
				return (nuint)Unsafe.SizeOf<T>();


			return (nuint)Marshal.SizeOf<T>();
		}

		//
		// Summary:
		//     Writes your own structure address into process' memory and gives you the address
		//     to which the structure has been directly written to.
		//
		// Parameters:
		//   bytesToWrite:
		//     A structure to be converted into individual bytes to be written onto the buffer.
		//
		//   marshalElement:
		//     Set this to true to marshal the given parameter before writing it to the buffer,
		//     else false.
		//
		//   alignment:
		//     The memory alignment of the item to be added to the buffer.
		//
		// Returns:
		//     Pointer to the newly written structure in memory. Null pointer, if it cannot
		//     fit into the buffer.
		public nuint Add<TStructure>(ref TStructure bytesToWrite, bool marshalElement = false) where TStructure : unmanaged {
			if (marshalElement)
				return AddMarshalled(bytesToWrite);
			var writePos = SecureWriteMemLoc(bytesToWrite, marshalElement);
			memory.Write(writePos, bytesToWrite);
			return writePos;
		}
		private nuint AddMarshalled<TStructure>(TStructure bytesToWrite) {
			var writePos = SecureWriteMemLoc(bytesToWrite, true);
			memory.WriteWithMarshalling(writePos, bytesToWrite);
			return writePos;
		}
		private nuint SecureWriteMemLoc<TStructure>(TStructure bytesToWrite, bool marshalElement) => SecureWriteMemLoc(GetSize<TStructure>(marshalElement));

		private nuint SecureWriteMemLoc(nuint size) {
			lock (writeLock) {
				var writePos = nextFreeBlockOffset;
				if (size + nextFreeBlockOffset > AllocSize)
					throw new InsufficientMemoryException($"Tried to allocate: {size} and total size for our allocation is: {AllocSize} and next free block offset: {nextFreeBlockOffset}");
				nextFreeBlockOffset += size;
				var addy = writePos + BaseAddress;
				return addy;
			}
		}
		public nuint Add<TStructure>(ref TStructure bytesToWrite) where TStructure : struct {
			return AddMarshalled(bytesToWrite);
		}

		public nuint Add(Span<byte> bytesToWrite) => AddBytes(bytesToWrite);
		public nuint AddBytes(Span<byte> bytesToWrite) {
			var writePos = SecureWriteMemLoc((nuint)bytesToWrite.Length);
			memory.WriteRaw(writePos, bytesToWrite);
			return writePos;
		}




		// TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
		~PrivateMemoryBufferCompat() {
			// Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
			Dispose(disposing: false);
		}

		public void Dispose() {
			// Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
			Dispose(disposing: true);
			GC.SuppressFinalize(this);
		}
	}
}
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
