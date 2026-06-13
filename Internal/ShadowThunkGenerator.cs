using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace IL2CppSharp.Hooking.Internal;

/// <summary>
/// Creates managed wrapper delegates that automatically append a MethodInfo pointer
/// as an extra parameter when calling a native function (trampoline).
///
/// Uses DynamicMethod + calli to support any number of parameters.
/// Delegate types passed to CreateDelegate should NOT include the methodInfo parameter.
/// </summary>
internal static class ShadowThunkGenerator
{
    // Keep delegates alive to prevent GC from collecting them
    private static readonly List<Delegate> _keepAlive = [];
    private static readonly Dictionary<(IntPtr target, IntPtr extra, Type delegateType), Delegate> _cache = [];
    private static readonly object _lock = new();

    /// <summary>
    /// Create a delegate of type T that calls the target native function
    /// with an extra IntPtr argument (methodInfo) appended after all declared parameters.
    /// </summary>
    public static T CreateDelegate<T>(IntPtr target, IntPtr extraArg) where T : Delegate
    {
        var key = (target, extraArg, typeof(T));
        lock (_lock)
        {
            if (_cache.TryGetValue(key, out var cached))
                return (T)cached;

            var invokeMethod = typeof(T).GetMethod("Invoke")!;
            var paramTypes = invokeMethod.GetParameters().Select(p => p.ParameterType).ToArray();
            var returnType = invokeMethod.ReturnType;

            // Native function params = clean params + IntPtr (methodInfo)
            var nativeParamTypes = new Type[paramTypes.Length + 1];
            Array.Copy(paramTypes, nativeParamTypes, paramTypes.Length);
            nativeParamTypes[paramTypes.Length] = typeof(IntPtr);

            var dm = new DynamicMethod(
                $"ShadowThunk_{typeof(T).Name}",
                returnType,
                paramTypes,
                typeof(ShadowThunkGenerator).Module,
                skipVisibility: true);

            var il = dm.GetILGenerator();

            // Load all clean params
            for (int i = 0; i < paramTypes.Length; i++)
                il.Emit(OpCodes.Ldarg, i);

            // Load extra arg (methodInfo)
            il.Emit(OpCodes.Ldc_I8, (long)extraArg);
            il.Emit(OpCodes.Conv_I);

            // Load target function pointer
            il.Emit(OpCodes.Ldc_I8, (long)target);
            il.Emit(OpCodes.Conv_I);

            // calli with unmanaged cdecl convention
            il.EmitCalli(OpCodes.Calli, CallingConvention.Cdecl, returnType, nativeParamTypes);

            il.Emit(OpCodes.Ret);

            var del = (T)dm.CreateDelegate(typeof(T));
            _keepAlive.Add(del);
            _cache[key] = del;
            return del;
        }
    }

}
