using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using IL2CppSharp.Hooking;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace IL2CppSharp.Hooking.Internal;

/// <summary>
/// Iced-based inline hook with proper RIP-relative instruction relocation.
/// Replaces the naive 14-byte copy approach that breaks on RIP-relative instructions.
/// </summary>
internal static unsafe class InlineHook
{
    private const int MinHookSize = 14; // mov rax, imm64 (10) + jmp rax (2) + 2 nop
    private const int MaxPrologueRead = 64;

    /// <summary>
    /// Install an inline hook at targetAddress, redirecting to detourAddress.
    /// Returns the trampoline address that calls the original function.
    /// Throws on failure.
    /// </summary>
    public static InlineHookResult Install(IntPtr targetAddress, IntPtr detourAddress, IHookLogger log, string name)
    {
        var result = TryInstall(targetAddress, detourAddress, log, name, out string error);
        if (result == null)
            throw new InvalidOperationException(error);
        return result.Value;
    }

    /// <summary>
    /// Try to install an inline hook. Returns null if relocation fails
    /// (e.g., IP-relative operand too far). Sets error message on failure.
    /// </summary>
    public static InlineHookResult? TryInstall(IntPtr targetAddress, IntPtr detourAddress,
        IHookLogger log, string name, out string error)
    {
        error = null;

        // Decode prologue with Iced to find clean instruction boundary >= 14 bytes
        var reader = new UnsafeCodeReader((byte*)targetAddress, MaxPrologueRead);
        var decoder = Decoder.Create(64, reader, (ulong)targetAddress, DecoderOptions.None);

        var prologueInstrs = new List<Instruction>();
        int totalBytes = 0;

        while (totalBytes < MinHookSize)
        {
            var instr = decoder.Decode();
            if (instr.IsInvalid)
            {
                error = $"[InlineHook] Invalid instruction at offset {totalBytes} in prologue of {name}";
                return null;
            }
            prologueInstrs.Add(instr);
            totalBytes += instr.Length;
        }

        log?.Debug($"[InlineHook] {name}: prologue {prologueInstrs.Count} instructions, {totalBytes} bytes");

        // Save original bytes for unhook
        byte[] originalBytes = new byte[totalBytes];
        Marshal.Copy(targetAddress, originalBytes, 0, totalBytes);

        // Allocate trampoline: relocated prologue + absolute jump back
        int trampolineMaxSize = totalBytes * 2 + 64;
        IntPtr trampoline = WindowsMemory.VirtualAlloc(
            IntPtr.Zero, (UIntPtr)trampolineMaxSize,
            WindowsMemory.MEM_COMMIT | WindowsMemory.MEM_RESERVE,
            WindowsMemory.PAGE_EXECUTE_READWRITE);
        if (trampoline == IntPtr.Zero)
        {
            error = $"[InlineHook] Failed to allocate trampoline memory for {name}";
            return null;
        }

        // Use BlockEncoder to relocate prologue instructions to trampoline address
        var codeWriter = new UnsafeCodeWriter((byte*)trampoline, trampolineMaxSize);
        var instrBlock = new InstructionBlock(codeWriter, prologueInstrs, (ulong)trampoline);

        if (!BlockEncoder.TryEncode(64, instrBlock, out string errorMsg, out _, BlockEncoderOptions.None))
        {
            error = $"[InlineHook] BlockEncoder failed for {name}: {errorMsg}";
            log?.Debug(error);
            return null;
        }

        int relocatedSize = codeWriter.Position;
        log?.Debug($"[InlineHook] {name}: relocated prologue {relocatedSize} bytes at trampoline 0x{trampoline:X}");

        // Append absolute jump back to original code after stolen bytes
        byte* tramp = (byte*)trampoline;
        var jumpAsm = new Assembler(64);
        jumpAsm.mov(rax, (ulong)(targetAddress + totalBytes));
        jumpAsm.jmp(rax);

        var jumpWriter = new UnsafeCodeWriter(tramp + relocatedSize, trampolineMaxSize - relocatedSize);
        jumpAsm.Assemble(jumpWriter, (ulong)(trampoline + relocatedSize));

        int totalTrampolineSize = relocatedSize + jumpWriter.Position;
        WindowsMemory.FlushInstructionCache(
            WindowsMemory.GetCurrentProcess(), trampoline, (UIntPtr)totalTrampolineSize);

        // Install 14-byte absolute jump at target
        if (!WindowsMemory.VirtualProtect(targetAddress, (UIntPtr)totalBytes,
            WindowsMemory.PAGE_EXECUTE_READWRITE, out uint oldProtect))
        {
            error = $"[InlineHook] VirtualProtect failed for {name}: {Marshal.GetLastWin32Error()}";
            return null;
        }

        byte* target = (byte*)targetAddress;
        // mov rax, detourAddress
        target[0] = 0x48;
        target[1] = 0xB8;
        *(IntPtr*)(target + 2) = detourAddress;
        // jmp rax
        target[10] = 0xFF;
        target[11] = 0xE0;
        // NOP any remaining stolen bytes
        for (int i = 12; i < totalBytes; i++)
            target[i] = 0x90;

        WindowsMemory.VirtualProtect(targetAddress, (UIntPtr)totalBytes, oldProtect, out _);
        WindowsMemory.FlushInstructionCache(
            WindowsMemory.GetCurrentProcess(), targetAddress, (UIntPtr)totalBytes);

        log?.Info($"[InlineHook] {name}: installed 0x{targetAddress:X} -> 0x{detourAddress:X} (trampoline=0x{trampoline:X})");

        return new InlineHookResult
        {
            TrampolineAddress = trampoline,
            OriginalBytes = originalBytes
        };
    }

    /// <summary>
    /// Restore original bytes at the hook target.
    /// </summary>
    public static void Uninstall(IntPtr targetAddress, byte[] originalBytes)
    {
        if (targetAddress == IntPtr.Zero || originalBytes == null || originalBytes.Length == 0)
            return;

        if (WindowsMemory.VirtualProtect(targetAddress, (UIntPtr)originalBytes.Length,
            WindowsMemory.PAGE_EXECUTE_READWRITE, out uint oldProtect))
        {
            Marshal.Copy(originalBytes, 0, targetAddress, originalBytes.Length);
            WindowsMemory.VirtualProtect(targetAddress, (UIntPtr)originalBytes.Length, oldProtect, out _);
            WindowsMemory.FlushInstructionCache(
                WindowsMemory.GetCurrentProcess(), targetAddress, (UIntPtr)originalBytes.Length);
        }
    }

    internal struct InlineHookResult
    {
        public IntPtr TrampolineAddress;
        public byte[] OriginalBytes;
    }

    #region Iced Helpers

    private sealed class UnsafeCodeReader(byte* code, int length) : CodeReader
    {
        private readonly byte* _code = code;
        private readonly int _length = length;
        private int _position = 0;

        public override int ReadByte()
        {
            if (_position >= _length)
                return -1;
            return _code[_position++];
        }
    }


    #endregion
}
