# IL2CppSharp.Hooking

Shared hook engine for IL2CPP and HybridCLR runtimes.

## Role

- Hooks interpreter methods, AOT/native IL2CPP methods, and raw exports.
- Centralizes hook state so multiple plugins do not patch the same target independently.
- Provides a BepInEx-independent core API. BepInEx logging lives in `IL2CppSharp.Hooking.BepInEx`.

## Depends on

- `IL2CppSharp`
- `SNWCreations.Il2CppInterop.Runtime`

## Used by

- `AstralParty.Modding`
- `AstralPartyMod`
- `APCP`
- `EventNotifier`
- `BIEScriptRunner`

## Public build notes

- This is a standalone library repository, not a BepInEx plugin by itself.
- The package depends on the SNWCreations Il2CppInterop runtime fork because the hook engine uses `HybridCLRCompat`.
- If you need to test against local package feeds or source checkouts, copy `Directory.Build.props.example` to `Directory.Build.props` and set the documented properties.
- BepInEx hosts should reference `IL2CppSharp.Hooking.BepInEx` and call:

```csharp
HookEngine.Initialize(new BepInExHookLogger(Logger));
```

## Breaking migration

- `BepInEx.HybridCLR.Hooking` is now `IL2CppSharp.Hooking`.
- `HybridCLR.RuntimeHooks` is now `IL2CppSharp.Hooking`.
- `HybridCLR.RuntimeHooks.BepInEx` is now `IL2CppSharp.Hooking.BepInEx`.
- `IRuntimeHookLogger` is now `IHookLogger`.
- `BepInExRuntimeHookLogger` is now `BepInExHookLogger`.
- No compatibility shim is provided.

## Build

```bash
dotnet build client-plugin/IL2CppSharp.Hooking/IL2CppSharp.Hooking.csproj -c Release /p:GeneratePackageOnBuild=false
```

## License

Apache 2.0. See [LICENSE](LICENSE).
