using System;
using System.Runtime.InteropServices;
using IL2CppSharp.Hooking.Internal;

namespace IL2CppSharp.Hooking;

public enum HookStrategy
{
    None = 0,
    InlineHook = 1,
    PointerSwap = 2,
    InterpreterDispatcher = 3,
    NativeExportInline = 4,
    InterpreterBridgeDetour = 5,
}

/// <summary>
/// Handle for a native hook, provides access to the original method via trampoline.
/// </summary>
public readonly struct HookHandle
{
    public readonly IntPtr MethodInfoPtr;
    public readonly IntPtr TrampolineAddress;

    /// <summary>
    /// Shadow copy of the MethodInfo with interpreter state intact.
    /// Use this pointer as the MethodInfo argument when calling the original method
    /// through the trampoline. The real MethodInfo is rewritten to route bridge,
    /// interpreter-call, and runtime-invoke paths through the detour.
    /// For non-interpreter hooks, this equals MethodInfoPtr.
    /// </summary>
    public readonly IntPtr ShadowMethodInfo;

    /// <summary>
    /// The actual strategy used to install this hook.
    /// </summary>
    public readonly HookStrategy Strategy;

    /// <summary>
    /// True if this hook intercepts at the interpreter level (via InterpreterDispatcher).
    /// Interpreter dispatcher hooks do not expose a trampoline for GetOriginal.
    /// </summary>
    public readonly bool IsInterpreterHook;

    internal HookHandle(IntPtr methodInfoPtr, IntPtr trampolineAddress, IntPtr shadowMethodInfo = default,
        bool isInterpreterHook = false, HookStrategy strategy = HookStrategy.None)
    {
        MethodInfoPtr = methodInfoPtr;
        TrampolineAddress = trampolineAddress;
        ShadowMethodInfo = shadowMethodInfo != IntPtr.Zero ? shadowMethodInfo : methodInfoPtr;
        IsInterpreterHook = isInterpreterHook;
        Strategy = strategy != HookStrategy.None
            ? strategy
            : (isInterpreterHook ? HookStrategy.InterpreterDispatcher : HookStrategy.InlineHook);
    }

    /// <summary>
    /// Get a delegate to call the original (unhooked) method.
    /// T should be a clean delegate type WITHOUT the methodInfo parameter.
    /// The returned delegate automatically appends the correct MethodInfo pointer.
    /// Not applicable for interpreter-level hooks (InterpreterDispatcher).
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the hook is an interpreter hook or the trampoline is null.
    /// </exception>
    public T GetOriginal<T>() where T : Delegate
    {
        if (IsInterpreterHook)
            throw new InvalidOperationException(
                "GetOriginal is not supported for interpreter-level hooks. " +
                "Use HookInterpreter pre/post callbacks for dispatcher-level interception.");

        if (TrampolineAddress == IntPtr.Zero)
            throw new InvalidOperationException(
                "Trampoline address is null — hook may not have been installed correctly.");

        if (Strategy == HookStrategy.NativeExportInline)
            return Marshal.GetDelegateForFunctionPointer<T>(TrampolineAddress);

        DelegateSignatureValidator.ValidateOriginalDelegate<T>(MethodInfoPtr, $"0x{MethodInfoPtr:X} ({Strategy})");

        IntPtr methodInfo = ShadowMethodInfo != IntPtr.Zero ? ShadowMethodInfo : MethodInfoPtr;
        return ShadowThunkGenerator.CreateDelegate<T>(TrampolineAddress, methodInfo);
    }

    /// <summary>
    /// Remove this hook.
    /// </summary>
    public bool Unhook() => HookEngine.Unhook(MethodInfoPtr);

    public bool IsValid => MethodInfoPtr != IntPtr.Zero &&
                           (IsInterpreterHook || TrampolineAddress != IntPtr.Zero);
}
