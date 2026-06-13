using System;
using Iced.Intel;

namespace IL2CppSharp.Hooking.Internal;

/// <summary>
/// Iced CodeWriter that writes directly to an unmanaged buffer.
/// </summary>
internal sealed unsafe class UnsafeCodeWriter(byte* buffer, int maxLength) : CodeWriter
{
    private readonly byte* _buffer = buffer;
    private readonly int _maxLength = maxLength;
    private int _position;

    public int Position => _position;

    public override void WriteByte(byte value)
    {
        if (_position >= _maxLength)
            throw new InvalidOperationException("UnsafeCodeWriter buffer overflow");
        _buffer[_position++] = value;
    }
}
