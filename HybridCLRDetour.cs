using System;
using System.Reflection;
using Il2CppInterop.Runtime.Injection;

namespace IL2CppSharp.Hooking;

internal readonly struct HybridCLRMethodInfoState(
    IntPtr methodPointer,
    IntPtr virtualMethodPointer,
    IntPtr invokerMethod,
    IntPtr interpData,
    IntPtr methodPointerCallByInterp,
    IntPtr virtualMethodPointerCallByInterp,
    bool isInterpterImpl,
    bool initInterpCallMethodPointer)
{
    public readonly IntPtr MethodPointer = methodPointer;
    public readonly IntPtr VirtualMethodPointer = virtualMethodPointer;
    public readonly IntPtr InvokerMethod = invokerMethod;
    public readonly IntPtr InterpData = interpData;
    public readonly IntPtr MethodPointerCallByInterp = methodPointerCallByInterp;
    public readonly IntPtr VirtualMethodPointerCallByInterp = virtualMethodPointerCallByInterp;
    public readonly bool IsInterpterImpl = isInterpterImpl;
    public readonly bool InitInterpCallMethodPointer = initInterpCallMethodPointer;
}

/// <summary>
/// HybridCLR method helpers used by the hook engine.
/// </summary>
internal static class HybridCLRDetour
{
    /// <summary>
    /// Set to true for older HybridCLR MethodInfo layouts where interpreter flags are stored
    /// after the three HybridCLR extension pointers instead of in MethodInfo.bitfield.
    /// </summary>
    public static bool UseLegacyMethodInfoLayout
    {
        get => HybridCLRCompat.UseLegacyMethodInfoLayout;
        set => HybridCLRCompat.UseLegacyMethodInfoLayout = value;
    }

    /// <summary>
    /// Detect whether the current runtime exposes HybridCLR RuntimeApi internal calls.
    /// </summary>
    public static bool IsHybridCLRRuntime() => HybridCLRCompat.IsHybridCLRRuntime();

    /// <summary>
    /// Check if a method is implemented by the HybridCLR interpreter using managed MethodInfo.
    /// </summary>
    public static bool IsInterpreterMethod(MethodInfo methodInfo)
    {
        if (methodInfo == null)
            return false;

        IntPtr ptr = GetNativeMethodInfoPointer(methodInfo);
        return IsInterpreterMethod(ptr);
    }

    /// <summary>
    /// Check if a method is implemented by the HybridCLR interpreter using native pointer.
    /// </summary>
    public static bool IsInterpreterMethod(IntPtr methodInfoPtr)
    {
        if (methodInfoPtr == IntPtr.Zero)
            return false;

        try
        {
            return HybridCLRCompat.IsInterpreterMethod(methodInfoPtr);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Prepare a HybridCLR interpreter method for detouring.
    /// Duplicates the bridge code and updates methodPointer to the copy.
    /// </summary>
    public static bool PrepareMethodForDetour(IntPtr methodInfoPtr, IHookLogger log = null, string methodName = null)
    {
        log?.Info($"[HybridCLRDetour] PrepareMethodForDetour: {methodName ?? "unknown"}");

        if (methodInfoPtr == IntPtr.Zero)
            return false;

        try
        {
            return HybridCLRCompat.PrepareMethodForDetour(methodInfoPtr);
        }
        catch (Exception ex)
        {
            log?.Warning($"[HybridCLRDetour] PrepareMethodForDetour failed: {ex.Message}");
            return false;
        }
    }

    internal static HybridCLRMethodInfoState? CaptureMethodInfoState(IntPtr methodInfoPtr)
    {
        if (methodInfoPtr == IntPtr.Zero) return null;

        var methodInfo = HybridCLRCompat.WrapMethodInfo(methodInfoPtr);
        if (methodInfo == null) return null;

        return new HybridCLRMethodInfoState(
            methodInfo.MethodPointer,
            methodInfo.VirtualMethodPointer,
            methodInfo.InvokerMethod,
            methodInfo.InterpData,
            methodInfo.MethodPointerCallByInterp,
            methodInfo.VirtualMethodPointerCallByInterp,
            methodInfo.IsInterpterImpl,
            methodInfo.InitInterpCallMethodPointer);
    }

    internal static void RestoreMethodInfoState(IntPtr methodInfoPtr, HybridCLRMethodInfoState state)
    {
        if (methodInfoPtr == IntPtr.Zero) return;

        var methodInfo = HybridCLRCompat.WrapMethodInfo(methodInfoPtr);
        if (methodInfo == null) return;

        methodInfo.MethodPointer = state.MethodPointer;
        methodInfo.VirtualMethodPointer = state.VirtualMethodPointer;
        methodInfo.InvokerMethod = state.InvokerMethod;
        methodInfo.InterpData = state.InterpData;
        methodInfo.MethodPointerCallByInterp = state.MethodPointerCallByInterp;
        methodInfo.VirtualMethodPointerCallByInterp = state.VirtualMethodPointerCallByInterp;
        methodInfo.IsInterpterImpl = state.IsInterpterImpl;
        methodInfo.InitInterpCallMethodPointer = state.InitInterpCallMethodPointer;
    }

    /// <summary>
    /// Set the invoker_method field on a MethodInfo to a custom invoker.
    /// </summary>
    public static void SetInvokerMethod(IntPtr methodInfoPtr, IntPtr invokerPtr)
    {
        if (methodInfoPtr == IntPtr.Zero || invokerPtr == IntPtr.Zero) return;

        var methodInfo = HybridCLRCompat.WrapMethodInfo(methodInfoPtr);
        if (methodInfo != null)
            methodInfo.InvokerMethod = invokerPtr;
    }

    /// <summary>
    /// Clear the isInterpreterImpl flag so the interpreter dispatches through methodPointer.
    /// </summary>
    public static void ClearInterpreterFlag(IntPtr methodInfoPtr)
    {
        if (methodInfoPtr == IntPtr.Zero) return;

        var methodInfo = HybridCLRCompat.WrapMethodInfo(methodInfoPtr);
        if (methodInfo != null)
            methodInfo.IsInterpterImpl = false;
    }

    /// <summary>
    /// Set the interpreter-call method pointers used by HybridCLR interpreter dispatch.
    /// </summary>
    public static void SetInterpCallMethodPointers(IntPtr methodInfoPtr, IntPtr newPointer)
    {
        if (methodInfoPtr == IntPtr.Zero || newPointer == IntPtr.Zero) return;

        var methodInfo = HybridCLRCompat.WrapMethodInfo(methodInfoPtr);
        if (methodInfo == null) return;

        methodInfo.MethodPointerCallByInterp = newPointer;
        methodInfo.VirtualMethodPointerCallByInterp = newPointer;
    }

    /// <summary>
    /// Ensure the InitInterpCallMethodPointer flag is set.
    /// </summary>
    public static void SetInitInterpCallMethodPointer(IntPtr methodInfoPtr)
    {
        if (methodInfoPtr == IntPtr.Zero) return;

        var methodInfo = HybridCLRCompat.WrapMethodInfo(methodInfoPtr);
        if (methodInfo != null)
            methodInfo.InitInterpCallMethodPointer = true;
    }

    /// <summary>
    /// Set the MethodPointer field on a MethodInfo struct.
    /// </summary>
    public static void SetMethodPointer(IntPtr methodInfoPtr, IntPtr newPointer)
    {
        if (methodInfoPtr == IntPtr.Zero) return;

        var methodInfo = HybridCLRCompat.WrapMethodInfo(methodInfoPtr);
        if (methodInfo != null)
            methodInfo.MethodPointer = newPointer;
    }

    private static IntPtr GetNativeMethodInfoPointer(MethodInfo methodInfo)
    {
        if (methodInfo == null)
            return IntPtr.Zero;

        try
        {
            var field = methodInfo.DeclaringType?.GetField("NativeMethodInfoPtr_" + methodInfo.Name,
                BindingFlags.NonPublic | BindingFlags.Static);

            if (field != null)
                return (IntPtr)field.GetValue(null);

            var ptrField = typeof(MethodBase).GetField("m_methodPtr",
                BindingFlags.NonPublic | BindingFlags.Instance);
            if (ptrField != null)
                return (IntPtr)ptrField.GetValue(methodInfo);
        }
        catch
        {
            // Best-effort only.
        }

        return IntPtr.Zero;
    }
}
