using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using IL2CppSharp.Hooking;
using Iced.Intel;
using IL2CppSharp;

namespace IL2CppSharp.Hooking.Internal;

/// <summary>
/// Hooks InterpFrameGroup::EnterFrameFromInterpreter to intercept interpreter-to-interpreter calls.
/// This function is called for every interp-to-interp call (CALL_INTERP_RET/CALL_INTERP_VOID),
/// giving us the MethodInfo* to check against our hook table.
/// </summary>
internal static unsafe class InterpreterDispatcher
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr EnterFrameDelegate(IntPtr interpFrameGroup, IntPtr methodInfo, IntPtr argBase);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr LeaveFrameDelegate(IntPtr interpFrameGroup);

    private static readonly Dictionary<IntPtr, HookEntry> _hookTable = [];
    private static readonly object _lock = new();
    private static EnterFrameDelegate _originalEnterFrame;
    private static EnterFrameDelegate _enterFrameDetour;
    private static LeaveFrameDelegate _originalLeaveFrame;
    private static LeaveFrameDelegate _leaveFrameDetour;
    private static IHookLogger _log = NoOpHookLogger.Instance;
    private static bool _installed;
    private static bool _hasAnyPostHooks;
    private static bool _leaveFrameHooked;
    private static IntPtr _enterFrameAddr; // saved for deferred LeaveFrame finding

    // MachineState field offsets (verified at runtime)
    private const int MachineState_FrameBase = 0x18;
    private const int MachineState_FrameTopIdx = 0x20;
    private const int InterpFrame_Size = 0x40;

    private struct HookEntry
    {
        public InterpreterPreHookCallback PreHook;
        public InterpreterPostHookCallback PostHook;
        public string Name;
    }

    /// <summary>
    /// Ensure the dispatcher is installed. Safe to call multiple times.
    /// </summary>
    internal static void EnsureInstalled(IHookLogger log)
    {
        if (_installed) return;

        lock (_lock)
        {
            if (_installed) return;
            if (log != null && ReferenceEquals(_log, NoOpHookLogger.Instance))
                _log = log;

            IntPtr enterFrameAddr = FindEnterFrameFromInterpreter();
            if (enterFrameAddr == IntPtr.Zero)
                throw new InvalidOperationException(
                    "[InterpreterDispatcher] Failed to find EnterFrameFromInterpreter");

            _log.Info($"[InterpreterDispatcher] EnterFrameFromInterpreter at 0x{enterFrameAddr:X}");

            // Hook EnterFrameFromInterpreter (pre-hook dispatch)
            _enterFrameDetour = DispatchEnterFrame;
            IntPtr enterDetourAddr = Marshal.GetFunctionPointerForDelegate(_enterFrameDetour);
            var enterResult = InlineHook.Install(enterFrameAddr, enterDetourAddr, _log,
                "EnterFrameFromInterpreter");
            _originalEnterFrame =
                Marshal.GetDelegateForFunctionPointer<EnterFrameDelegate>(enterResult.TrampolineAddress);
            _log.Info(
                $"[InterpreterDispatcher] EnterFrame hook installed, trampoline at 0x{enterResult.TrampolineAddress:X}");

            // Hook LeaveFrame (post-hook dispatch) — deferred until first post-hook is registered
            // Finding LeaveFrame via forward scan is unreliable (early ret in functions),
            // so we only attempt it when actually needed.
            _enterFrameAddr = enterFrameAddr;
            _log.Info("[InterpreterDispatcher] LeaveFrame hook deferred until post-hook registered");

            _installed = true;
        }
    }

    /// <summary>
    /// Register with explicit pre/post hooks.
    /// </summary>
    internal static void Register(IntPtr methodInfoPtr,
        InterpreterPreHookCallback preHook, InterpreterPostHookCallback postHook, string name)
    {
        lock (_lock)
        {
            _hookTable[methodInfoPtr] = new HookEntry
            {
                PreHook = preHook, PostHook = postHook, Name = name
            };
            if (postHook != null)
            {
                _hasAnyPostHooks = true;
                EnsureLeaveFrameHooked();
            }
            _log.Info(
                $"[InterpreterDispatcher] Registered: {name} (pre={preHook != null}, post={postHook != null})");
        }
    }

    internal static bool Unregister(IntPtr methodInfoPtr)
    {
        lock (_lock)
        {
            if (_hookTable.Remove(methodInfoPtr))
            {
                _log.Info($"[InterpreterDispatcher] Unregistered: 0x{methodInfoPtr:X}");
                return true;
            }
            return false;
        }
    }

    /// <summary>
    /// Detour for EnterFrameFromInterpreter. Called on EVERY interpreter-to-interpreter call.
    /// Handles registered pre-hooks.
    /// </summary>
    private static IntPtr DispatchEnterFrame(IntPtr interpFrameGroup, IntPtr methodInfo, IntPtr argBase)
    {
        if (_hookTable.TryGetValue(methodInfo, out var entry))
        {
            try
            {
                entry.PreHook?.Invoke(methodInfo, argBase);
            }
            catch (Exception ex)
            {
                _log.Error(
                    $"[InterpreterDispatcher] Pre-hook error in {entry.Name}: {ex.Message}");
            }
        }

        // Always call original — the Execute loop needs the frame to be set up
        return _originalEnterFrame(interpFrameGroup, methodInfo, argBase);
    }

    /// <summary>
    /// Detour for LeaveFrame. Called on EVERY interpreter frame exit.
    /// Reads the top frame's method before popping to fire post-hooks.
    /// </summary>
    private static IntPtr DispatchLeaveFrame(IntPtr interpFrameGroup)
    {
        IntPtr leavingMethod = IntPtr.Zero;

        // Only do the expensive read if we have any post-hooks registered
        if (_hasAnyPostHooks)
        {
            leavingMethod = ReadTopFrameMethod(interpFrameGroup);
        }

        // Call original LeaveFrame (pops the frame)
        IntPtr result = _originalLeaveFrame(interpFrameGroup);

        // Fire post-hook if the leaving method was hooked
        if (leavingMethod != IntPtr.Zero
            && _hookTable.TryGetValue(leavingMethod, out var entry)
            && entry.PostHook != null)
        {
            try
            {
                entry.PostHook(leavingMethod);
            }
            catch (Exception ex)
            {
                _log.Error(
                    $"[InterpreterDispatcher] Post-hook error in {entry.Name}: {ex.Message}");
            }
        }

        return result;
    }

    /// <summary>
    /// Read the MethodInfo* of the top interpreter frame from InterpFrameGroup internals.
    /// Layout: InterpFrameGroup._machineState (offset 0) -> MachineState._frameBase/TopIdx
    /// </summary>
    private static IntPtr ReadTopFrameMethod(IntPtr interpFrameGroup)
    {
        try
        {
            IntPtr machineState = *(IntPtr*)interpFrameGroup;
            IntPtr frameBase = *(IntPtr*)((byte*)machineState + MachineState_FrameBase);
            int frameTopIdx = *(int*)((byte*)machineState + MachineState_FrameTopIdx);
            if (frameTopIdx <= 0 || frameBase == IntPtr.Zero) return IntPtr.Zero;

            IntPtr topFrame = (IntPtr)((byte*)frameBase + (frameTopIdx - 1) * InterpFrame_Size);
            return *(IntPtr*)topFrame; // InterpFrame.method at offset 0
        }
        catch
        {
            return IntPtr.Zero;
        }
    }

    /// <summary>
    /// Install the LeaveFrame hook on demand (first time a post-hook is registered).
    /// Must be called under _lock.
    /// </summary>
    private static void EnsureLeaveFrameHooked()
    {
        if (_leaveFrameHooked || _enterFrameAddr == IntPtr.Zero) return;

        IntPtr leaveFrameAddr = FindLeaveFrame(_enterFrameAddr);
        if (leaveFrameAddr == IntPtr.Zero)
        {
            _log.Warning(
                "[InterpreterDispatcher] Failed to find LeaveFrame, post-hooks will not work");
            return;
        }

        _log.Info($"[InterpreterDispatcher] LeaveFrame at 0x{leaveFrameAddr:X}");
        _leaveFrameDetour = DispatchLeaveFrame;
        IntPtr leaveDetourAddr = Marshal.GetFunctionPointerForDelegate(_leaveFrameDetour);
        var leaveResult = InlineHook.Install(leaveFrameAddr, leaveDetourAddr, _log, "LeaveFrame");
        _originalLeaveFrame =
            Marshal.GetDelegateForFunctionPointer<LeaveFrameDelegate>(leaveResult.TrampolineAddress);
        _leaveFrameHooked = true;
        _log.Info(
            $"[InterpreterDispatcher] LeaveFrame hook installed, trampoline at 0x{leaveResult.TrampolineAddress:X}");
    }

    #region Find EnterFrameFromInterpreter

    private const int MaxPrologueInstructions = 60;
    private const int MaxBridgeDisasmBytes = 256;
    private const int MaxBackwardScan = 512;

    /// <summary>
    /// Find EnterFrameFromInterpreter by:
    /// 1. Find Interpreter::Execute via bridge stub disassembly
    /// 2. Find EnterFrameFromNative in Execute's prologue
    /// 3. Scan backwards from EnterFrameFromNative for the previous function
    /// </summary>
    private static IntPtr FindEnterFrameFromInterpreter()
    {
        IntPtr executeAddr = FindExecuteAddress();
        if (executeAddr == IntPtr.Zero) return IntPtr.Zero;

        _log.Info($"[InterpreterDispatcher] Interpreter::Execute at 0x{executeAddr:X}");

        IntPtr enterFrameNative = FindEnterFrameFromNativeInPrologue(executeAddr);
        if (enterFrameNative == IntPtr.Zero)
        {
            _log.Error("[InterpreterDispatcher] Failed to find EnterFrameFromNative");
            return IntPtr.Zero;
        }

        _log.Info($"[InterpreterDispatcher] EnterFrameFromNative at 0x{enterFrameNative:X}");

        IntPtr enterFrameInterp = ScanBackwardsForPreviousFunction(enterFrameNative);
        if (enterFrameInterp == IntPtr.Zero)
        {
            _log.Error("[InterpreterDispatcher] Failed to find EnterFrameFromInterpreter");
            return IntPtr.Zero;
        }

        // Verify: the function should read [rdx+0x58] (interpData) and do a sub
        if (!VerifyEnterFrameFromInterpreter(enterFrameInterp))
        {
            _log.Warning(
                $"[InterpreterDispatcher] Verification failed for 0x{enterFrameInterp:X}, using anyway");
        }

        return enterFrameInterp;
    }

    /// <summary>
    /// Find EnterFrameFromNative by disassembling Execute's prologue.
    /// Pattern: after the interpData check (cmp [reg+0x58], reg), find the call
    /// preceded by lea rcx, [rbp+XX] (loading InterpFrameGroup*).
    /// </summary>
    private static IntPtr FindEnterFrameFromNativeInPrologue(IntPtr executeAddr)
    {
        var reader = new UnsafeCodeReader((byte*)executeAddr, 512);
        var decoder = Decoder.Create(64, reader, (ulong)executeAddr, DecoderOptions.None);

        bool foundInterpDataCheck = false;
        bool sawLeaRcxRbp = false;

        for (int i = 0; i < MaxPrologueInstructions; i++)
        {
            var instr = decoder.Decode();
            if (instr.IsInvalid) break;

            // Look for cmp [reg+0x58], reg — the interpData null check
            if (!foundInterpDataCheck && instr.Mnemonic == Mnemonic.Cmp
                && instr.MemoryDisplacement64 == 0x58)
            {
                foundInterpDataCheck = true;
                _log.Debug(
                    $"[InterpreterDispatcher] interpData check at 0x{instr.IP:X}");
                continue;
            }

            if (!foundInterpDataCheck) continue;

            // After interpData check, look for lea rcx, [rbp+XX]
            if (instr.Mnemonic == Mnemonic.Lea
                && instr.Op0Register == Iced.Intel.Register.RCX
                && instr.MemoryBase == Iced.Intel.Register.RBP)
            {
                sawLeaRcxRbp = true;
                continue;
            }

            // If we saw lea rcx, [rbp+XX] recently and this is a CALL, it's EnterFrameFromNative
            if (sawLeaRcxRbp && instr.FlowControl == FlowControl.Call
                && instr.Op0Kind == OpKind.NearBranch64)
            {
                return (IntPtr)instr.NearBranchTarget;
            }

            // Reset if we see another instruction between lea and call
            if (sawLeaRcxRbp && instr.Mnemonic != Mnemonic.Mov)
                sawLeaRcxRbp = false;
        }

        return IntPtr.Zero;
    }

    /// <summary>
    /// Scan backwards from a function address to find the previous function.
    /// Looks for int3 (0xCC) padding that separates functions.
    /// </summary>
    private static IntPtr ScanBackwardsForPreviousFunction(IntPtr functionAddr)
    {
        byte* p = (byte*)functionAddr;

        // Scan backwards looking for at least 2 consecutive 0xCC (int3) bytes
        for (int i = 2; i <= MaxBackwardScan; i++)
        {
            if (*(p - i) == 0xCC && *(p - i - 1) == 0xCC)
            {
                // Found int3 padding. Scan forward to find function start.
                byte* start = p - i;
                while (*start == 0xCC) start++;
                return (IntPtr)start;
            }
        }

        return IntPtr.Zero;
    }

    /// <summary>
    /// Verify a candidate is EnterFrameFromInterpreter by checking for the
    /// characteristic sub instruction (maxStackSize - argStackObjectSize).
    /// EnterFrameFromInterpreter reads [rdx+0x58] and does a sub with [reg+0x20].
    /// EnterFrameFromNative does NOT have this subtraction.
    /// </summary>
    private static bool VerifyEnterFrameFromInterpreter(IntPtr addr)
    {
        var reader = new UnsafeCodeReader((byte*)addr, 128);
        var decoder = Decoder.Create(64, reader, (ulong)addr, DecoderOptions.None);

        bool foundInterpDataRead = false;
        bool foundSub = false;

        for (int i = 0; i < 30; i++)
        {
            var instr = decoder.Decode();
            if (instr.IsInvalid || instr.FlowControl == FlowControl.Return) break;

            // Check for reading offset 0x58 (interpData)
            if (instr.MemoryDisplacement64 == 0x58)
                foundInterpDataRead = true;

            // Check for sub with offset 0x20 (argStackObjectSize)
            if (instr.Mnemonic == Mnemonic.Sub && instr.MemoryDisplacement64 == 0x20)
                foundSub = true;
        }

        return foundInterpDataRead && foundSub;
    }

    /// <summary>
    /// Find LeaveFrame by scanning forward from EnterFrameFromInterpreter.
    /// In Engine.cpp, the order is: EnterFrameFromInterpreter, EnterFrameFromNative, LeaveFrame.
    /// We skip two functions forward from EnterFrameFromInterpreter.
    /// </summary>
    private static IntPtr FindLeaveFrame(IntPtr enterFrameFromInterpreter)
    {
        // Skip past EnterFrameFromInterpreter -> EnterFrameFromNative -> LeaveFrame
        IntPtr enterFrameFromNative = ScanForwardToNextFunction(enterFrameFromInterpreter);
        if (enterFrameFromNative == IntPtr.Zero)
        {
            _log.Error("[InterpreterDispatcher] Failed to find EnterFrameFromNative by forward scan");
            return IntPtr.Zero;
        }

        _log.Debug($"[InterpreterDispatcher] EnterFrameFromNative (forward) at 0x{enterFrameFromNative:X}");

        IntPtr leaveFrame = ScanForwardToNextFunction(enterFrameFromNative);
        if (leaveFrame == IntPtr.Zero)
        {
            _log.Error("[InterpreterDispatcher] Failed to find LeaveFrame by forward scan");
            return IntPtr.Zero;
        }

        return leaveFrame;
    }

    /// <summary>
    /// Scan forward from a function start to find the next function.
    /// Disassembles until finding a RET that's followed by int3 padding or a function prologue,
    /// skipping early returns (RET followed by more code in the same function).
    /// </summary>
    private static IntPtr ScanForwardToNextFunction(IntPtr funcAddr)
    {
        var reader = new UnsafeCodeReader((byte*)funcAddr, 2048);
        var decoder = Decoder.Create(64, reader, (ulong)funcAddr, DecoderOptions.None);

        for (int i = 0; i < 400; i++)
        {
            var instr = decoder.Decode();
            if (instr.IsInvalid) break;

            if (instr.FlowControl != FlowControl.Return) continue;

            // Found a RET — check what comes after it
            byte* afterRet = (byte*)(instr.IP + (ulong)instr.Length);

            // Skip int3 padding (if any)
            byte* p = afterRet;
            int ccCount = 0;
            while (*p == 0xCC && ccCount < 64) { p++; ccCount++; }

            // If we found int3 padding, the next function starts after it
            if (ccCount >= 1)
            {
                if (*p != 0x00 && *p != 0xCC) return (IntPtr)p;
                return IntPtr.Zero; // hit end of section
            }

            // No int3 padding — check if the byte after ret looks like a function prologue
            if (IsFunctionPrologue(afterRet))
                return (IntPtr)afterRet;

            // Otherwise this was an early return; continue disassembling
        }

        return IntPtr.Zero;
    }

    /// <summary>
    /// Check if bytes at the given address look like a typical x64 function prologue.
    /// Used to detect function boundaries when there's no int3 padding.
    /// </summary>
    private static bool IsFunctionPrologue(byte* p)
    {
        byte b = *p;
        // push rbx(53) rbp(55) rsi(56) rdi(57) — common callee-saved register saves
        if (b >= 0x53 && b <= 0x57) return true;
        // push r12-r15: REX.B(41) + push(54-57)
        if (b == 0x41 && *(p + 1) >= 0x54 && *(p + 1) <= 0x57) return true;
        // sub rsp, imm8: 48 83 EC xx
        if (b == 0x48 && *(p + 1) == 0x83 && *(p + 2) == 0xEC) return true;
        // sub rsp, imm32: 48 81 EC xx xx xx xx
        if (b == 0x48 && *(p + 1) == 0x81 && *(p + 2) == 0xEC) return true;
        return false;
    }

    #endregion

    #region Find Interpreter::Execute

    /// <summary>
    /// Find Interpreter::Execute by disassembling an interpreter method's
    /// Native2Managed bridge stub. The bridge calls Execute as:
    ///   Interpreter::Execute(method, args, ret)
    /// We find the CALL instruction target.
    /// </summary>
    private static IntPtr FindExecuteAddress()
    {
        IntPtr probeMethod = FindAnyInterpreterMethod();
        if (probeMethod == IntPtr.Zero)
        {
            _log.Error("[InterpreterDispatcher] No interpreter method found for probe");
            return IntPtr.Zero;
        }

        IntPtr bridgeAddr = *(IntPtr*)probeMethod;
        if (bridgeAddr == IntPtr.Zero)
        {
            _log.Error("[InterpreterDispatcher] Probe method has null methodPointer");
            return IntPtr.Zero;
        }

        _log.Info($"[InterpreterDispatcher] Probing bridge at 0x{bridgeAddr:X}");

        var reader = new UnsafeCodeReader((byte*)bridgeAddr, MaxBridgeDisasmBytes);
        var decoder = Decoder.Create(64, reader, (ulong)bridgeAddr, DecoderOptions.None);

        while (decoder.IP < (ulong)bridgeAddr + MaxBridgeDisasmBytes)
        {
            var instr = decoder.Decode();
            if (instr.IsInvalid) break;

            if (instr.FlowControl == FlowControl.Call && instr.Op0Kind == OpKind.NearBranch64)
            {
                var target = (IntPtr)instr.NearBranchTarget;
                if (IsValidFunctionTarget(target))
                    return target;
            }

            if (instr.FlowControl == FlowControl.Return)
                break;
        }

        _log.Error($"[InterpreterDispatcher] No CALL found in bridge at 0x{bridgeAddr:X}");
        return IntPtr.Zero;
    }

    private static IntPtr FindAnyInterpreterMethod()
    {
        _log.Debug("[InterpreterDispatcher] Scanning loaded IL2CPP images for an interpreter method");

        [DllImport("GameAssembly", CallingConvention = CallingConvention.Cdecl)]
        static extern IntPtr il2cpp_domain_get();

        [DllImport("GameAssembly", CallingConvention = CallingConvention.Cdecl)]
        static extern IntPtr il2cpp_domain_get_assemblies(IntPtr domain, ref uint size);

        [DllImport("GameAssembly", CallingConvention = CallingConvention.Cdecl)]
        static extern IntPtr il2cpp_assembly_get_image(IntPtr assembly);

        [DllImport("GameAssembly", CallingConvention = CallingConvention.Cdecl)]
        static extern uint il2cpp_image_get_class_count(IntPtr image);

        [DllImport("GameAssembly", CallingConvention = CallingConvention.Cdecl)]
        static extern IntPtr il2cpp_image_get_class(IntPtr image, uint index);

        [DllImport("GameAssembly", CallingConvention = CallingConvention.Cdecl)]
        static extern IntPtr il2cpp_class_get_methods(IntPtr klass, ref IntPtr iter);

        IntPtr domain = il2cpp_domain_get();
        if (domain == IntPtr.Zero) return IntPtr.Zero;

        uint asmCount = 0;
        IntPtr asmArray = il2cpp_domain_get_assemblies(domain, ref asmCount);
        if (asmArray == IntPtr.Zero || asmCount == 0) return IntPtr.Zero;

        for (uint a = 0; a < asmCount; a++)
        {
            IntPtr asm = *(IntPtr*)((byte*)asmArray + a * (uint)IntPtr.Size);
            if (asm == IntPtr.Zero) continue;

            IntPtr image = il2cpp_assembly_get_image(asm);
            if (image == IntPtr.Zero) continue;

            uint classCount = il2cpp_image_get_class_count(image);

            for (uint c = 0; c < classCount; c++)
            {
                IntPtr klass = il2cpp_image_get_class(image, c);
                if (klass == IntPtr.Zero) continue;

                IntPtr iter = IntPtr.Zero;
                IntPtr method;
                while ((method = il2cpp_class_get_methods(klass, ref iter)) != IntPtr.Zero)
                {
                    if (!HybridCLRDetour.IsInterpreterMethod(method)) continue;

                    IntPtr ptr = *(IntPtr*)method;
                    if (ptr != IntPtr.Zero)
                    {
                        _log.Debug($"[InterpreterDispatcher] Found interpreter probe method 0x{method:X}");
                        return method;
                    }
                }
            }
        }

        return IntPtr.Zero;
    }

    private static bool IsValidFunctionTarget(IntPtr target)
    {
        if (target == IntPtr.Zero) return false;
        try
        {
            byte* p = (byte*)target;
            return *p != 0x00 && *p != 0xCC;
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region Iced Helper

    private sealed class UnsafeCodeReader(byte* code, int length) : CodeReader
    {
        private readonly byte* _code = code;
        private readonly int _length = length;
        private int _position;

        public override int ReadByte()
        {
            if (_position >= _length) return -1;
            return _code[_position++];
        }
    }

    #endregion
}
