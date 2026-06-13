namespace IL2CppSharp.Hooking;

/// <summary>
/// Logging abstraction used by the core runtime hook engine.
/// </summary>
public interface IHookLogger
{
    void Debug(string message);

    void Info(string message);

    void Warning(string message);

    void Error(string message);
}

internal sealed class NoOpHookLogger : IHookLogger
{
    public static readonly NoOpHookLogger Instance = new();

    private NoOpHookLogger()
    {
    }

    public void Debug(string message)
    {
    }

    public void Info(string message)
    {
    }

    public void Warning(string message)
    {
    }

    public void Error(string message)
    {
    }
}
