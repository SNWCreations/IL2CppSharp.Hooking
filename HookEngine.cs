using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Il2CppInterop.Runtime;
using Il2CppInterop.Runtime.Injection;
using Il2CppInterop.Runtime.Startup;
using IL2CppSharp;
using IL2CppSharp.Hooking.Internal;

namespace IL2CppSharp.Hooking;

/// <summary>
/// Called before a hooked interpreter method executes.
/// </summary>
/// <param name="methodInfo">The MethodInfo* of the method being called</param>
/// <param name="argBase">StackObject* base pointer for interpreter arguments</param>
public delegate void InterpreterPreHookCallback(IntPtr methodInfo, IntPtr argBase);

/// <summary>
/// Called after a hooked interpreter method returns.
/// </summary>
/// <param name="methodInfo">The MethodInfo* of the method that just returned</param>
public delegate void InterpreterPostHookCallback(IntPtr methodInfo);

/// <summary>
/// Unified native IL2CPP method hooking engine.
/// Supports HybridCLR interpreter methods (InterpreterDispatcher), AOT methods (Iced inline hook),
/// and raw native exports.
/// All plugins share one hook registry, preventing double-hook conflicts.
/// </summary>
public static unsafe class HookEngine
{
    private static IHookLogger _log = NoOpHookLogger.Instance;
    private static bool _hasLogger;

    private static readonly Dictionary<IntPtr, HookInfo> _activeHooks = [];
    private static readonly object _lock = new();
    private static readonly Dictionary<IntPtr, Delegate> _delegateReferences = [];
    private static readonly Dictionary<IntPtr, IntPtr> _hookedAddresses = [];

    private struct HookInfo
    {
        public IntPtr OriginalMethodPointer;
        public IntPtr AddressDedupKey;
        public IntPtr TrampolineAddress;
        public IntPtr ShadowMethodInfo;
        public IDetour NativeDetour;
        public HybridCLRMethodInfoState? HybridCLRRestoreState;
        public byte[] OriginalBytes;
        public string MethodName;
        public bool IsInterpreterHook;
        public HookStrategy Strategy;
        public bool RestoreMethodPointer;
        public IntPtr MethodPointerRestoreValue;
        public bool RestoreVirtualMethodPointer;
        public IntPtr VirtualMethodPointerRestoreValue;
        public bool RestoreMethodPointerCallByInterp;
        public IntPtr MethodPointerCallByInterpRestoreValue;
        public bool RestoreVirtualMethodPointerCallByInterp;
        public IntPtr VirtualMethodPointerCallByInterpRestoreValue;
    }

    /// <summary>
    /// Initialize the hook engine. Call once at plugin startup.
    /// Multiple calls are safe; the first logger wins.
    /// </summary>
    public static void Initialize(IHookLogger logger = null)
    {
        if (logger != null && !_hasLogger)
        {
            _log = logger;
            _hasLogger = true;
        }

        InvokerGenerator.Initialize(_log);
        _log.Info("[HookEngine] Initialized");
    }

    /// <summary>
    /// Hook an IL2CPP method by MethodInfo pointer.
    /// Auto-detects HybridCLR interpreter vs AOT and uses the appropriate strategy.
    /// </summary>
    public static HookHandle Hook(IntPtr methodInfoPtr, Delegate detourFunc, string methodName = null)
    {
        if (methodInfoPtr == IntPtr.Zero)
            throw new ArgumentNullException(nameof(methodInfoPtr));
        if (detourFunc == null)
            throw new ArgumentNullException(nameof(detourFunc));

        lock (_lock)
        {
            if (_activeHooks.ContainsKey(methodInfoPtr))
            {
                _log.Warning($"[HookEngine] Method already hooked: {methodName ?? "unknown"}");
                var existing = _activeHooks[methodInfoPtr];
                return new HookHandle(methodInfoPtr, existing.TrampolineAddress, existing.ShadowMethodInfo,
                    existing.IsInterpreterHook, existing.Strategy);
            }

            methodName ??= $"Method@0x{methodInfoPtr:X}";

            IntPtr originalMethodPointer = *(IntPtr*)methodInfoPtr;
            if (originalMethodPointer == IntPtr.Zero)
                throw new InvalidOperationException($"Method pointer is null: {methodName}");

            DelegateSignatureValidator.ValidateHookDelegate(methodInfoPtr, detourFunc, methodName);

            bool isInterpreterMethod = HybridCLRDetour.IsInterpreterMethod(methodInfoPtr);

            // Skip address dedup for interpreter methods — their bridge gets duplicated by PrepareMethodForDetour
            if (!isInterpreterMethod && _hookedAddresses.TryGetValue(originalMethodPointer, out _))
            {
                _log.Warning($"[HookEngine] Address 0x{originalMethodPointer:X} already hooked, skipping: {methodName}");
                return new HookHandle(IntPtr.Zero, IntPtr.Zero);
            }

            _log.Info($"[HookEngine] {methodName}: ptr=0x{originalMethodPointer:X}, interpreter={isInterpreterMethod}");

            HookInfo hookInfo;

            if (isInterpreterMethod)
            {
                hookInfo = HookInterpreterMethod(methodInfoPtr, detourFunc, originalMethodPointer, methodName);
            }
            else
            {
                hookInfo = HookNativeMethod(methodInfoPtr, detourFunc, originalMethodPointer, methodName);
            }

            _activeHooks[methodInfoPtr] = hookInfo;
            if (hookInfo.AddressDedupKey != IntPtr.Zero)
                _hookedAddresses[hookInfo.AddressDedupKey] = methodInfoPtr;
            _delegateReferences[methodInfoPtr] = detourFunc;

            return new HookHandle(methodInfoPtr, hookInfo.TrampolineAddress, hookInfo.ShadowMethodInfo,
                hookInfo.IsInterpreterHook, hookInfo.Strategy);
        }
    }

    /// <summary>
    /// Hook a method by type name and method name (resolves via Il2CppReflection).
    /// </summary>
    public static HookHandle Hook(string fullTypeName, string methodName, Delegate detourFunc, int paramCount = -1)
    {
        IntPtr methodInfo = Il2CppReflection.FindMethod(fullTypeName, methodName, paramCount);
        if (methodInfo == IntPtr.Zero)
            throw new InvalidOperationException($"Method not found: {fullTypeName}.{methodName}");

        return Hook(methodInfo, detourFunc, $"{fullTypeName}.{methodName}");
    }

    /// <summary>
    /// Hook a raw native export (non-IL2CPP). Skips all IL2CPP/HybridCLR logic.
    /// Uses Iced-based inline hook with proper prologue relocation.
    /// </summary>
    public static HookHandle HookNativeExport(IntPtr targetAddress, Delegate detourFunc, string name = null)
    {
        if (targetAddress == IntPtr.Zero)
            throw new ArgumentNullException(nameof(targetAddress));
        if (detourFunc == null)
            throw new ArgumentNullException(nameof(detourFunc));

        lock (_lock)
        {
            if (_hookedAddresses.TryGetValue(targetAddress, out _))
            {
                _log.Warning($"[HookEngine] Native address 0x{targetAddress:X} already hooked");
                return new HookHandle(IntPtr.Zero, IntPtr.Zero);
            }

            name ??= $"Native@0x{targetAddress:X}";
            IntPtr detourAddress = Marshal.GetFunctionPointerForDelegate(detourFunc);

            _log.Info(
                $"[HookEngine] {name}: hooking native export at 0x{targetAddress:X}, detour at 0x{detourAddress:X}");

            var result = InlineHook.Install(targetAddress, detourAddress, _log, name);

            // Use targetAddress as the "methodInfoPtr" key for native exports
            var hookInfo = new HookInfo
            {
                OriginalMethodPointer = targetAddress,
                AddressDedupKey = targetAddress,
                TrampolineAddress = result.TrampolineAddress,
                OriginalBytes = result.OriginalBytes,
                MethodName = name,
                Strategy = HookStrategy.NativeExportInline,
            };

            _activeHooks[targetAddress] = hookInfo;
            _hookedAddresses[targetAddress] = targetAddress;
            _delegateReferences[targetAddress] = detourFunc;

            return new HookHandle(targetAddress, result.TrampolineAddress, strategy: HookStrategy.NativeExportInline);
        }
    }

    /// <summary>
    /// Hook an interpreter method with explicit pre/post callbacks.
    /// Pre-hook fires before the method executes, post-hook fires after it returns.
    /// </summary>
    public static HookHandle HookInterpreter(IntPtr methodInfoPtr,
        InterpreterPreHookCallback preHook = null,
        InterpreterPostHookCallback postHook = null,
        string name = null)
    {
        if (methodInfoPtr == IntPtr.Zero)
            throw new ArgumentNullException(nameof(methodInfoPtr));
        if (preHook == null && postHook == null)
            throw new ArgumentException("At least one of preHook or postHook must be provided");

        lock (_lock)
        {
            name ??= $"InterpMethod@0x{methodInfoPtr:X}";

            if (_activeHooks.ContainsKey(methodInfoPtr))
            {
                _log.Warning($"[HookEngine] Method already hooked: {name}");
                return new HookHandle(methodInfoPtr, IntPtr.Zero, isInterpreterHook: true,
                    strategy: HookStrategy.InterpreterDispatcher);
            }

            InterpreterDispatcher.EnsureInstalled(_log);
            InterpreterDispatcher.Register(methodInfoPtr, preHook, postHook, name);

            var hookInfo = new HookInfo
            {
                OriginalMethodPointer = IntPtr.Zero,
                TrampolineAddress = IntPtr.Zero,
                MethodName = name,
                IsInterpreterHook = true,
                Strategy = HookStrategy.InterpreterDispatcher,
            };

            _activeHooks[methodInfoPtr] = hookInfo;
            if (preHook != null) _delegateReferences[methodInfoPtr] = preHook;
            else _delegateReferences[methodInfoPtr] = postHook;

            _log.Info($"[HookEngine] Hooked {name} (pre={preHook != null}, post={postHook != null}, strategy={HookStrategy.InterpreterDispatcher})");
            return new HookHandle(methodInfoPtr, IntPtr.Zero, isInterpreterHook: true,
                strategy: HookStrategy.InterpreterDispatcher);
        }
    }

    /// <summary>
    /// Hook an interpreter method by type/method name with explicit pre/post callbacks.
    /// </summary>
    public static HookHandle HookInterpreter(string fullTypeName, string methodName,
        InterpreterPreHookCallback preHook = null,
        InterpreterPostHookCallback postHook = null,
        int paramCount = -1)
    {
        IntPtr methodInfo = Il2CppReflection.FindMethod(fullTypeName, methodName, paramCount);
        if (methodInfo == IntPtr.Zero)
            throw new InvalidOperationException($"Method not found: {fullTypeName}.{methodName}");

        return HookInterpreter(methodInfo, preHook, postHook, $"{fullTypeName}.{methodName}");
    }

    /// <summary>
    /// Remove a hook and restore the original method.
    /// </summary>
    public static bool Unhook(IntPtr methodInfoPtr)
    {
        lock (_lock)
        {
            if (!_activeHooks.TryGetValue(methodInfoPtr, out var hookInfo))
                return false;

            if (hookInfo.Strategy == HookStrategy.InterpreterDispatcher)
            {
                InterpreterDispatcher.Unregister(methodInfoPtr);
            }
            else
            {
                hookInfo.NativeDetour?.Dispose();

                if (hookInfo.HybridCLRRestoreState.HasValue)
                    HybridCLRDetour.RestoreMethodInfoState(methodInfoPtr, hookInfo.HybridCLRRestoreState.Value);
                else
                    RestorePointerFields(methodInfoPtr, hookInfo);

                if (hookInfo.OriginalBytes != null)
                    InlineHook.Uninstall(hookInfo.OriginalMethodPointer, hookInfo.OriginalBytes);

                if (hookInfo.ShadowMethodInfo != IntPtr.Zero && hookInfo.ShadowMethodInfo != methodInfoPtr)
                    Marshal.FreeHGlobal(hookInfo.ShadowMethodInfo);

                if (hookInfo.AddressDedupKey != IntPtr.Zero &&
                    _hookedAddresses.TryGetValue(hookInfo.AddressDedupKey, out var primary) &&
                    primary == methodInfoPtr)
                    _hookedAddresses.Remove(hookInfo.AddressDedupKey);
            }

            _activeHooks.Remove(methodInfoPtr);
            _delegateReferences.Remove(methodInfoPtr);

            _log.Info($"[HookEngine] Unhooked {hookInfo.MethodName}");
            return true;
        }
    }

    /// <summary>
    /// Check if a method is currently hooked.
    /// </summary>
    public static bool IsHooked(IntPtr methodInfoPtr)
    {
        lock (_lock) { return _activeHooks.ContainsKey(methodInfoPtr); }
    }

    #region Private Helpers

    private static HookInfo HookInterpreterMethod(IntPtr methodInfoPtr, Delegate detourFunc,
        IntPtr originalMethodPointer, string methodName)
    {
        _log.Info($"[HookEngine] {methodName}: interpreter method, using bridge-dup + flag-clear");

        IntPtr detourAddress = Marshal.GetFunctionPointerForDelegate(detourFunc);

        if (!HybridCLRDetour.PrepareMethodForDetour(methodInfoPtr, _log, methodName))
            throw new InvalidOperationException($"Failed to prepare interpreter method: {methodName}");

        // After PrepareMethodForDetour:
        //   MethodPointer = duplicated bridge (copy of original bridge code)
        //   isInterpterImpl = true (unchanged)

        IntPtr duplicatedBridge = *(IntPtr*)methodInfoPtr;
        _log.Info($"[HookEngine] Duplicated bridge at: 0x{duplicatedBridge:X}");

        // Preparation duplicates the shared bridge and leaves the method in an unhooked prepared state.
        // Use that state as the restore baseline so repeated hook/unhook cycles stay consistent with
        // HybridCLR preparation cache.
        var restoreState = HybridCLRDetour.CaptureMethodInfoState(methodInfoPtr);
        if (!restoreState.HasValue)
            throw new InvalidOperationException($"Failed to capture interpreter MethodInfo state: {methodName}");

        // Create shadow MethodInfo BEFORE any modifications.
        // The shadow preserves the original state (isInterpterImpl=true, all flags intact).
        // When calling the original method, pass this shadow so the bridge/interpreter
        // can find the correct flags and lazily initialize interpData.
        const int methodInfoSize = 0x80;
        IntPtr shadowMethodInfo = Marshal.AllocHGlobal(methodInfoSize);
        Buffer.MemoryCopy((void*)methodInfoPtr, (void*)shadowMethodInfo, methodInfoSize, methodInfoSize);
        // Shadow's methodPointer should point to duplicated bridge (not the original shared bridge)
        *(IntPtr*)shadowMethodInfo = duplicatedBridge;
        _log.Info($"[HookEngine] {methodName}: shadow MethodInfo created at 0x{shadowMethodInfo:X}");

        // Use DetourProvider to hook the duplicated bridge.
        // The trampoline from this detour is how we call the original method.
        var nativeDetour = CreateDetour(duplicatedBridge, detourFunc);
        nativeDetour.Apply();

        // CRITICAL: Clear isInterpterImpl so interpreter takes the managed2native path
        // which reads methodPointer (our detour) instead of interpData (direct interp call).
        HybridCLRDetour.ClearInterpreterFlag(methodInfoPtr);

        // Set methodPointer to detour so the managed2native bridge calls our code.
        // The duplicated bridge is now only reachable via the DetourProvider trampoline.
        HybridCLRDetour.SetMethodPointer(methodInfoPtr, detourAddress);

        // Also update virtualMethodPointer (offset 0x08) so vtable dispatch hits our detour.
        // PrepareMethodForDetour sets both MethodPointer and VirtualMethodPointer to the
        // duplicated bridge, but SetMethodPointer only updates offset 0x00.
        // Without this, AOT code calling this method virtually bypasses the hook entirely.
        IntPtr* virtualMethodPointer = (IntPtr*)((byte*)methodInfoPtr + 0x08);
        if (*virtualMethodPointer == originalMethodPointer || *virtualMethodPointer == duplicatedBridge)
            *virtualMethodPointer = detourAddress;

        // Route interpreter-to-native/direct interpreter call paths through the detour as well.
        HybridCLRDetour.SetInterpCallMethodPointers(methodInfoPtr, detourAddress);

        // Prevent InitAndGetInterpreterDirectlyCallMethodPointerSlow from
        // re-initializing and overwriting our pointers.
        HybridCLRDetour.SetInitInterpCallMethodPointer(methodInfoPtr);

        // Generate and install custom invoker to handle il2cpp_runtime_invoke and delegate paths.
        // Without this, InterpreterInvoke ignores methodPointer and enters the interpreter directly.
        try
        {
            IntPtr invoker = InvokerGenerator.GetOrCreateInvoker(methodInfoPtr, _log);
            if (invoker != IntPtr.Zero)
            {
                HybridCLRDetour.SetInvokerMethod(methodInfoPtr, invoker);
                _log.Info($"[HookEngine] {methodName}: custom invoker installed at 0x{invoker:X}");
            }
            else
            {
                _log.Warning($"[HookEngine] {methodName}: invoker generation failed, delegate/runtime_invoke path may not work");
            }
        }
        catch (Exception ex)
        {
            _log.Warning($"[HookEngine] {methodName}: invoker generation error: {ex.Message}");
        }

        var hookInfo = new HookInfo
        {
            OriginalMethodPointer = duplicatedBridge,
            TrampolineAddress = nativeDetour.OriginalTrampoline,
            ShadowMethodInfo = shadowMethodInfo,
            NativeDetour = nativeDetour,
            HybridCLRRestoreState = restoreState,
            OriginalBytes = null,
            MethodName = methodName,
            Strategy = HookStrategy.InterpreterBridgeDetour,
        };

        _log.Info($"[HookEngine] Hooked {methodName}: trampoline=0x{nativeDetour.OriginalTrampoline:X}, isInterpterImpl cleared, shadow=0x{shadowMethodInfo:X}");
        return hookInfo;
    }

    private static HookInfo HookNativeMethod(IntPtr methodInfoPtr, Delegate detourFunc,
        IntPtr originalMethodPointer, string methodName)
    {
        IntPtr methodPointer = *(IntPtr*)methodInfoPtr;
        if (methodPointer == IntPtr.Zero)
            throw new InvalidOperationException($"Method pointer is null: {methodName}");

        IntPtr detourAddress = Marshal.GetFunctionPointerForDelegate(detourFunc);
        var failureReasons = new List<string>();

        // Try inline hook first
        var result = InlineHook.TryInstall(methodPointer, detourAddress, _log, methodName, out string inlineError);
        if (result != null)
        {
            _log.Info($"[HookEngine] {methodName}: native method, using strategy={HookStrategy.InlineHook}");

            // Update the MethodInfo to point to our detour
            *(IntPtr*)methodInfoPtr = detourAddress;

            // Also update virtualMethodPointer if present (offset 0x08)
            IntPtr* virtualMethodPointer = (IntPtr*)((byte*)methodInfoPtr + 0x08);
            IntPtr originalVirtualMethodPointer = *virtualMethodPointer;
            bool restoreVirtualMethodPointer = false;
            if (*virtualMethodPointer == methodPointer)
            {
                *virtualMethodPointer = detourAddress;
                restoreVirtualMethodPointer = true;
            }

            var hookInfo = new HookInfo
            {
                OriginalMethodPointer = methodPointer,
                AddressDedupKey = methodPointer,
                TrampolineAddress = result.Value.TrampolineAddress,
                OriginalBytes = result.Value.OriginalBytes,
                MethodName = methodName,
                Strategy = HookStrategy.InlineHook,
                RestoreMethodPointer = true,
                MethodPointerRestoreValue = methodPointer,
                RestoreVirtualMethodPointer = restoreVirtualMethodPointer,
                VirtualMethodPointerRestoreValue = originalVirtualMethodPointer,
            };

            _log.Info($"[HookEngine] Hooked {methodName} (strategy={HookStrategy.InlineHook}): 0x{methodPointer:X} -> 0x{detourAddress:X}");
            return hookInfo;
        }
        failureReasons.Add(inlineError);

        // Fallback: pointer swap
        _log.Info($"[HookEngine] {methodName}: strategy {HookStrategy.InlineHook} not possible, trying {HookStrategy.PointerSwap}");
        var pointerSwap = HookViaPointerSwap(methodInfoPtr, methodPointer, detourAddress, methodName, out string pointerSwapError);
        if (pointerSwap != null)
            return pointerSwap.Value;
        failureReasons.Add(pointerSwapError);

        throw new InvalidOperationException(
            $"No viable hook strategy for {methodName}. " +
            string.Join(" | ", failureReasons));
    }

    /// <summary>
    /// Fallback hook strategy: directly overwrite MethodInfo function pointers.
    /// Used when InlineHook fails (e.g., IP-relative operands too far for relocation).
    /// Returns null on failure and sets an error message.
    /// </summary>
    private static HookInfo? HookViaPointerSwap(IntPtr methodInfoPtr, IntPtr originalPtr,
        IntPtr detourAddress, string methodName, out string error)
    {
        error = null;

        if (methodInfoPtr == IntPtr.Zero)
        {
            error = $"Pointer swap failed for {methodName}: MethodInfo pointer is null";
            return null;
        }
        if (originalPtr == IntPtr.Zero)
        {
            error = $"Pointer swap failed for {methodName}: original method pointer is null";
            return null;
        }
        if (detourAddress == IntPtr.Zero)
        {
            error = $"Pointer swap failed for {methodName}: detour address is null";
            return null;
        }

        // Must at least own methodPointer (offset 0x00) for the hook to be meaningful
        IntPtr currentMethodPointer = *(IntPtr*)methodInfoPtr;
        if (currentMethodPointer != originalPtr)
        {
            error = $"Pointer swap failed for {methodName}: MethodInfo.methodPointer changed " +
                    $"from expected 0x{originalPtr:X} to 0x{currentMethodPointer:X}";
            return null;
        }

        // Overwrite methodPointer (offset 0x00)
        *(IntPtr*)methodInfoPtr = detourAddress;
        if (*(IntPtr*)methodInfoPtr != detourAddress)
        {
            error = $"Pointer swap failed for {methodName}: unable to write methodPointer";
            return null;
        }

        // Overwrite virtualMethodPointer (offset 0x08) if it matches original
        IntPtr* vmp = (IntPtr*)((byte*)methodInfoPtr + 0x08);
        IntPtr originalVirtualMethodPointer = *vmp;
        bool restoreVirtualMethodPointer = false;
        if (*vmp == originalPtr)
        {
            *vmp = detourAddress;
            restoreVirtualMethodPointer = true;
        }

        // Overwrite methodPointerCallByInterp (offset 0x60) if it matches original
        IntPtr* mpcbi = (IntPtr*)((byte*)methodInfoPtr + 0x60);
        IntPtr originalMethodPointerCallByInterp = *mpcbi;
        bool restoreMethodPointerCallByInterp = false;
        if (*mpcbi == originalPtr)
        {
            *mpcbi = detourAddress;
            restoreMethodPointerCallByInterp = true;
        }

        // Overwrite virtualMethodPointerCallByInterp (offset 0x68) if it matches original
        IntPtr* vmpcbi = (IntPtr*)((byte*)methodInfoPtr + 0x68);
        IntPtr originalVirtualMethodPointerCallByInterp = *vmpcbi;
        bool restoreVirtualMethodPointerCallByInterp = false;
        if (*vmpcbi == originalPtr)
        {
            *vmpcbi = detourAddress;
            restoreVirtualMethodPointerCallByInterp = true;
        }

        _log.Info(
            $"[HookEngine] Hooked {methodName} (strategy={HookStrategy.PointerSwap}): 0x{originalPtr:X} -> 0x{detourAddress:X}");

        return new HookInfo
        {
            OriginalMethodPointer = originalPtr,
            AddressDedupKey = originalPtr,
            TrampolineAddress = originalPtr,
            MethodName = methodName,
            Strategy = HookStrategy.PointerSwap,
            RestoreMethodPointer = true,
            MethodPointerRestoreValue = originalPtr,
            RestoreVirtualMethodPointer = restoreVirtualMethodPointer,
            VirtualMethodPointerRestoreValue = originalVirtualMethodPointer,
            RestoreMethodPointerCallByInterp = restoreMethodPointerCallByInterp,
            MethodPointerCallByInterpRestoreValue = originalMethodPointerCallByInterp,
            RestoreVirtualMethodPointerCallByInterp = restoreVirtualMethodPointerCallByInterp,
            VirtualMethodPointerCallByInterpRestoreValue = originalVirtualMethodPointerCallByInterp,
        };
    }

    private static void RestorePointerFields(IntPtr methodInfoPtr, HookInfo hookInfo)
    {
        // Native exports are keyed by the target address rather than a MethodInfo.
        if (hookInfo.Strategy == HookStrategy.NativeExportInline)
            return;

        if (methodInfoPtr == IntPtr.Zero)
            return;

        if (hookInfo.RestoreMethodPointer)
            *(IntPtr*)methodInfoPtr = hookInfo.MethodPointerRestoreValue;

        if (hookInfo.RestoreVirtualMethodPointer)
            *(IntPtr*)((byte*)methodInfoPtr + 0x08) = hookInfo.VirtualMethodPointerRestoreValue;

        if (hookInfo.RestoreMethodPointerCallByInterp)
            *(IntPtr*)((byte*)methodInfoPtr + 0x60) = hookInfo.MethodPointerCallByInterpRestoreValue;

        if (hookInfo.RestoreVirtualMethodPointerCallByInterp)
            *(IntPtr*)((byte*)methodInfoPtr + 0x68) = hookInfo.VirtualMethodPointerCallByInterpRestoreValue;
    }

    #endregion


    /// <summary>
    /// Helper to call DetourProvider.Create with the runtime delegate type.
    /// </summary>
    private static IDetour CreateDetour(IntPtr target, Delegate detourFunc)
    {
        // DetourProvider.Create<TDelegate> requires a concrete type.
        // Use reflection to call it with the actual delegate type.
        var createMethod = Il2CppInteropRuntime.Instance.DetourProvider.GetType()
            .GetMethod("Create")!
            .MakeGenericMethod(detourFunc.GetType());
        return (IDetour)createMethod.Invoke(
            Il2CppInteropRuntime.Instance.DetourProvider, new object[] { target, detourFunc });
    }
}
