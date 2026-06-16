using System;
using System.Linq;
using System.Reflection;
using IL2CppSharp;

namespace IL2CppSharp.Hooking.Internal;

internal static class DelegateSignatureValidator
{
    public static void ValidateHookDelegate(IntPtr methodInfoPtr, Delegate detourFunc, string methodName)
    {
        if (methodInfoPtr == IntPtr.Zero || detourFunc == null)
            return;

        var sig = Il2CppReflection.GetMethodSignatureInfo(methodInfoPtr);
        ValidateReturnType(sig, detourFunc.GetType(), methodName, "Hook");

        var invoke = GetInvokeMethod(detourFunc.GetType());
        var parameters = invoke.GetParameters();
        int cleanParamCount = GetCleanAbiParameterCount(sig);
        int nativeParamCount = cleanParamCount + 1; // trailing MethodInfo*

        if (parameters.Length != cleanParamCount && parameters.Length != nativeParamCount)
        {
            throw new InvalidOperationException(
                $"Hook delegate signature mismatch for {methodName}: " +
                $"delegate {FormatDelegate(detourFunc.GetType())} has {parameters.Length} parameter(s), " +
                $"but the IL2CPP method is {(sig.IsInstance ? "instance" : "static")} with {sig.ParamCount} explicit parameter(s). " +
                $"Expected {cleanParamCount} parameter(s) without MethodInfo or {nativeParamCount} with trailing MethodInfo.");
        }

        if (parameters.Length == nativeParamCount && !IsNativePointerLike(parameters[^1].ParameterType))
        {
            throw new InvalidOperationException(
                $"Hook delegate signature mismatch for {methodName}: " +
                $"the trailing MethodInfo parameter must be IntPtr/nint, but delegate {FormatDelegate(detourFunc.GetType())} uses " +
                $"{FormatType(parameters[^1].ParameterType)}.");
        }
    }

    public static void ValidateOriginalDelegate<T>(IntPtr methodInfoPtr, string hookDescription) where T : Delegate
    {
        if (methodInfoPtr == IntPtr.Zero)
            return;

        var delegateType = typeof(T);
        var sig = Il2CppReflection.GetMethodSignatureInfo(methodInfoPtr);
        ValidateReturnType(sig, delegateType, hookDescription, "GetOriginal");

        var invoke = GetInvokeMethod(delegateType);
        int cleanParamCount = GetCleanAbiParameterCount(sig);
        int nativeParamCount = cleanParamCount + 1; // trailing MethodInfo*
        int actualParamCount = invoke.GetParameters().Length;

        if (actualParamCount == nativeParamCount)
        {
            throw new InvalidOperationException(
                $"GetOriginal delegate signature mismatch for {hookDescription}: " +
                $"delegate {FormatDelegate(delegateType)} includes the trailing MethodInfo parameter. " +
                $"GetOriginal appends the shadow MethodInfo automatically, so use a clean delegate with {cleanParamCount} parameter(s).");
        }

        if (actualParamCount != cleanParamCount)
        {
            throw new InvalidOperationException(
                $"GetOriginal delegate signature mismatch for {hookDescription}: " +
                $"delegate {FormatDelegate(delegateType)} has {actualParamCount} parameter(s), " +
                $"but expected {cleanParamCount} clean ABI parameter(s) for an {(sig.IsInstance ? "instance" : "static")} " +
                $"IL2CPP method with {sig.ParamCount} explicit parameter(s).");
        }
    }

    private static void ValidateReturnType(Il2CppReflection.MethodSignatureInfo sig, Type delegateType,
        string methodName, string usage)
    {
        var invoke = GetInvokeMethod(delegateType);
        Type returnType = invoke.ReturnType;

        bool expectsVoidReturn = sig.IsVoidReturn || sig.HasLargeStructReturn;
        if (expectsVoidReturn && returnType != typeof(void))
        {
            throw new InvalidOperationException(
                $"{usage} delegate return mismatch for {methodName}: delegate {FormatDelegate(delegateType)} returns " +
                $"{FormatType(returnType)}, but the IL2CPP method returns " +
                $"{(sig.HasLargeStructReturn ? "a large value type via hidden return buffer" : "void")}.");
        }

        if (!expectsVoidReturn && returnType == typeof(void))
        {
            throw new InvalidOperationException(
                $"{usage} delegate return mismatch for {methodName}: delegate {FormatDelegate(delegateType)} returns void, " +
                $"but the IL2CPP method return type is {sig.ReturnTypeEnum}.");
        }
    }

    private static int GetCleanAbiParameterCount(Il2CppReflection.MethodSignatureInfo sig)
    {
        int count = sig.ParamCount;
        if (sig.IsInstance)
            count++;

        // Windows x64 passes large value-type returns through a hidden first argument.
        if (sig.HasLargeStructReturn)
            count++;

        return count;
    }

    private static MethodInfo GetInvokeMethod(Type delegateType)
    {
        var invoke = delegateType.GetMethod("Invoke");
        if (invoke == null)
            throw new InvalidOperationException($"{delegateType.FullName} is not a delegate type.");
        return invoke;
    }

    private static bool IsNativePointerLike(Type type)
        => type == typeof(IntPtr) ||
           type == typeof(UIntPtr) ||
           type.IsPointer;

    private static string FormatDelegate(Type delegateType)
    {
        var invoke = GetInvokeMethod(delegateType);
        string parameters = string.Join(", ",
            invoke.GetParameters().Select(p => FormatType(p.ParameterType)));
        return $"{delegateType.FullName}({parameters}) -> {FormatType(invoke.ReturnType)}";
    }

    private static string FormatType(Type type)
        => type == typeof(void) ? "void" : type.FullName ?? type.Name;
}
