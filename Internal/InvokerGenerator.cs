using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using IL2CppSharp.Hooking;
using Iced.Intel;
using IL2CppSharp;
using static Iced.Intel.AssemblerRegisters;

namespace IL2CppSharp.Hooking.Internal;

/// <summary>
/// Generates x64 native invoker functions that bridge the IL2CPP invoker_method calling convention
/// to the native method calling convention. This allows hooked HybridCLR methods to be called
/// through il2cpp_runtime_invoke and delegate invoke paths.
///
/// Invoker input (x64 Windows ABI):
///   RCX = methodPointer (function to call)
///   RDX = method (MethodInfo*)
///   R8  = this (object pointer, or NULL for static)
///   R9  = args (void** - each element points to the arg value)
///   [RSP+0x28] = ret (void* - return value buffer)
///
/// Native method convention (IL2CPP):
///   Instance: methodPointer(this, arg0, arg1, ..., MethodInfo*)
///   Static:   methodPointer(arg0, arg1, ..., MethodInfo*)
///   Struct return > 8 bytes: hidden return pointer as first arg
/// </summary>
internal static unsafe class InvokerGenerator
{
    private static IHookLogger _log = NoOpHookLogger.Instance;
    private static readonly Dictionary<int, IntPtr> _cache = [];
    private static readonly object _lock = new();

    public static void Initialize(IHookLogger log)
    {
        if (log != null && ReferenceEquals(_log, NoOpHookLogger.Instance))
            _log = log;
    }

    /// <summary>
    /// Get or create a native invoker for the given method signature.
    /// </summary>
    public static IntPtr GetOrCreateInvoker(IntPtr methodInfoPtr, IHookLogger log)
    {
        if (log != null && ReferenceEquals(_log, NoOpHookLogger.Instance))
            _log = log;

        var sig = Il2CppReflection.GetMethodSignatureInfo(methodInfoPtr);
        int hash = Il2CppReflection.ComputeSignatureHash(in sig);

        lock (_lock)
        {
            if (_cache.TryGetValue(hash, out var cached))
            {
                _log.Debug($"[InvokerGenerator] Cache hit for hash=0x{hash:X8}");
                return cached;
            }
        }

        _log.Info($"[InvokerGenerator] Generating invoker: params={sig.ParamCount}, instance={sig.IsInstance}, " +
                  $"void={sig.IsVoidReturn}, largeRet={sig.HasLargeStructReturn}");

        IntPtr invoker = GenerateInvoker(in sig);

        if (invoker != IntPtr.Zero)
        {
            lock (_lock) { _cache[hash] = invoker; }
            _log.Info($"[InvokerGenerator] Generated invoker at 0x{invoker:X}");
        }
        else
        {
            _log.Error("[InvokerGenerator] Failed to generate invoker");
        }

        return invoker;
    }

    private static IntPtr GenerateInvoker(in Il2CppReflection.MethodSignatureInfo sig)
    {
        var asm = new Assembler(64);

        // Callee-saved registers we use: r12-r15, rbx, rdi, rsi
        // Save them + align stack
        asm.push(rbp);
        asm.mov(rbp, rsp);
        asm.push(rbx);
        asm.push(r12);
        asm.push(r13);
        asm.push(r14);
        asm.push(r15);
        asm.push(rdi);
        asm.push(rsi);

        // Save input parameters to callee-saved regs.
        // Win64 ABI: RCX=methodPointer, RDX=method, R8=this, R9=args, 5th arg (ret) on stack.
        //
        // 5th arg location: caller places it at [RSP+0x20] (after 0x20 shadow space).
        // CALL pushes return address (+8), then our push rbp (+8), so ret = [RBP+0x30].
        // Remaining pushes don't affect this since we address relative to RBP, not RSP.
        asm.mov(r14, rcx);  // r14 = methodPointer
        asm.mov(r15, rdx);  // r15 = method (MethodInfo*)
        asm.mov(r12, r8);   // r12 = this
        asm.mov(r13, r9);   // r13 = args
        asm.mov(rbx, __[rbp + 0x30]); // rbx = ret

        // Build the native argument list.
        // Order: [hiddenRetPtr] [this] [params...] [MethodInfo*]
        // Total native args count:
        int nativeArgCount = sig.ParamCount + 1; // +1 for MethodInfo* at end
        if (sig.IsInstance) nativeArgCount++;
        if (sig.HasLargeStructReturn) nativeArgCount++;

        // We need stack space for: shadow space (0x20) + stack args beyond 4
        int stackArgCount = Math.Max(nativeArgCount - 4, 0);
        // Stack alignment: 7 pushes (rbp + 6 regs) = 56 bytes, which restores 16-byte alignment
        // after the return address push. The sub rsp allocation must stay 16-byte aligned.
        int stackAlloc = 0x20 + stackArgCount * 8;
        if (stackAlloc % 16 != 0) stackAlloc += 8;
        asm.sub(rsp, stackAlloc);

        // rdi = index into native arg slots (0-based)
        // rsi = temp for loading args
        int argIdx = 0;

        // Hidden return pointer (large struct return > 8 bytes)
        if (sig.HasLargeStructReturn)
        {
            EmitSetNativeArg(asm, argIdx++, rbx); // ret buffer pointer
        }

        // this pointer for instance methods
        if (sig.IsInstance)
        {
            EmitSetNativeArg(asm, argIdx++, r12);
        }

        // Parameters from args array
        for (int i = 0; i < sig.ParamCount; i++)
        {
            bool isLargeStruct = sig.ParamValueSizes[i] > 8;

            // Load args[i] pointer: r13 + i*8
            asm.mov(rsi, __[r13 + i * 8]); // rsi = args[i] (pointer to value)

            if (isLargeStruct)
            {
                // Pass pointer directly for large structs
                EmitSetNativeArg(asm, argIdx++, rsi);
            }
            else
            {
                // Dereference: load 8 bytes from the pointed-to value
                asm.mov(rsi, __[rsi]);
                EmitSetNativeArg(asm, argIdx++, rsi);
            }
        }

        // MethodInfo* always last
        EmitSetNativeArg(asm, argIdx++, r15);

        // Call methodPointer
        asm.call(r14);

        // Store return value
        if (!sig.IsVoidReturn && !sig.HasLargeStructReturn)
        {
            // Small return value in RAX -> store to ret buffer
            // rbx = ret pointer (may be null if caller doesn't care)
            var skipStore = asm.CreateLabel();
            asm.test(rbx, rbx);
            asm.je(skipStore);
            asm.mov(__[rbx], rax);
            asm.Label(ref skipStore);
        }

        // Epilogue
        asm.add(rsp, stackAlloc);
        asm.pop(rsi);
        asm.pop(rdi);
        asm.pop(r15);
        asm.pop(r14);
        asm.pop(r13);
        asm.pop(r12);
        asm.pop(rbx);
        asm.pop(rbp);
        asm.ret();

        // Assemble to executable memory
        int bufferSize = 1024; // generous for any reasonable signature
        IntPtr code = WindowsMemory.VirtualAlloc(
            IntPtr.Zero, (UIntPtr)bufferSize,
            WindowsMemory.MEM_COMMIT | WindowsMemory.MEM_RESERVE,
            WindowsMemory.PAGE_EXECUTE_READWRITE);

        if (code == IntPtr.Zero)
            return IntPtr.Zero;

        var writer = new UnsafeCodeWriter((byte*)code, bufferSize);
        asm.Assemble(writer, (ulong)code);

        WindowsMemory.FlushInstructionCache(
            WindowsMemory.GetCurrentProcess(), code, (UIntPtr)writer.Position);

        return code;
    }

    /// <summary>
    /// Place a value into the Nth native argument slot.
    /// Args 0-3 go in RCX, RDX, R8, R9; args 4+ go on stack at [RSP+0x20+N*8].
    /// </summary>
    private static void EmitSetNativeArg(Assembler asm, int index, AssemblerRegister64 value)
    {
        switch (index)
        {
            case 0: asm.mov(rcx, value); break;
            case 1: asm.mov(rdx, value); break;
            case 2: asm.mov(r8, value); break;
            case 3: asm.mov(r9, value); break;
            default:
                // Stack args: [RSP + 0x20 + (index-4)*8]
                int offset = 0x20 + (index - 4) * 8;
                asm.mov(__[rsp + offset], value);
                break;
        }
    }

}
