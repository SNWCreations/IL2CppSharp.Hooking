using System;

namespace IL2CppSharp.Hooking;

/// <summary>
/// Lightweight wrapper over the interpreter's StackObject* argument base pointer.
/// Provides typed accessors for reading/writing arguments by index.
/// StackObject is 8 bytes on x64 (pointer-sized union of ptr/i64/f64).
///
/// For instance methods: index 0 = this, 1 = first param, 2 = second param, ...
/// For static methods:   index 0 = first param, 1 = second param, ...
/// </summary>
public readonly unsafe struct InterpreterArgs(IntPtr argBase)
{
    private const int StackObjectSize = 8;
    private readonly byte* _base = (byte*)argBase;

    public IntPtr this[int index] => *(IntPtr*)(_base + index * StackObjectSize);

    public IntPtr GetPtr(int index) => *(IntPtr*)(_base + index * StackObjectSize);
    public void SetPtr(int index, IntPtr value) => *(IntPtr*)(_base + index * StackObjectSize) = value;

    public int GetInt32(int index) => *(int*)(_base + index * StackObjectSize);
    public void SetInt32(int index, int value) => *(int*)(_base + index * StackObjectSize) = value;

    public long GetInt64(int index) => *(long*)(_base + index * StackObjectSize);
    public void SetInt64(int index, long value) => *(long*)(_base + index * StackObjectSize) = value;

    public float GetFloat(int index) => *(float*)(_base + index * StackObjectSize);
    public void SetFloat(int index, float value) => *(float*)(_base + index * StackObjectSize) = value;

    public double GetDouble(int index) => *(double*)(_base + index * StackObjectSize);
    public void SetDouble(int index, double value) => *(double*)(_base + index * StackObjectSize) = value;

    public bool GetBool(int index) => *(int*)(_base + index * StackObjectSize) != 0;
    public void SetBool(int index, bool value) => *(int*)(_base + index * StackObjectSize) = value ? 1 : 0;
}
