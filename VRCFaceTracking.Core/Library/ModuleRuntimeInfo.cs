using System.Diagnostics;
using System.Runtime.Loader;
using VRCFaceTracking.Core.Sandboxing;
using VRCFaceTracking.Core.Sandboxing.IPC;

namespace VRCFaceTracking.Core.Library;

public class ModuleRuntimeInfo
{
    // @NOTE: The following 4 properties should all be removed by the time sandboxing is done

#if true

    public ExtTrackingModule Module;
    public AssemblyLoadContext AssemblyLoadContext;
    public CancellationTokenSource UpdateCancellationToken;
    public Thread UpdateThread;

#endif

    /// <summary>
    /// Whether the module is active and will receive update events.
    /// </summary>
    public bool IsActive;
    /// <summary>
    /// The UDP port the sandbox process associated with this application is on
    /// </summary>
    public int SandboxProcessPort;
    /// <summary>
    /// The PID of a sandbox process
    /// </summary>
    public int SandboxProcessPID;
    /// <summary>
    /// The path to the module the sandbox shall load
    /// </summary>
    public string SandboxModulePath;
    /// <summary>
    /// The process hosting the sandboxed module
    /// </summary>
    public Process Process;
    /// <summary>
    /// The module's retreived metadata
    /// </summary>
    public ModuleMetadataInternal ModuleInformation;
    /// <summary>
    /// Module status
    /// </summary>
    public ModuleState Status = ModuleState.Uninitialized;
    /// <summary>
    /// The class name of the module. Retrieved through a metadata packet.
    /// </summary>
    public string ModuleClassName;

    /// <summary>
    /// Whether this module supports eye tracking or not.
    /// </summary>
    public bool SupportsEyeTracking;
    /// <summary>
    /// Whether this module supports expression tracking or not.
    /// </summary>
    public bool SupportsExpressionTracking;
    public bool PrefersPushUpdates;

    /// <summary>
    /// Queue of packets to send
    /// </summary>
    public Queue<QueuedPacket> EventBus;

    /// <summary>
    /// Last time a ReplyUpdate packet was seen from this module.
    /// </summary>
    public long LastReplyUpdateTimestamp = Stopwatch.GetTimestamp();

    /// <summary>
    /// Number of stale watchdog kicks issued for this module.
    /// </summary>
    public int StaleKickCount;

    /// <summary>
    /// Number of restart attempts issued for this module.
    /// </summary>
    public int RestartCount;

    /// <summary>
    /// Whether a restart is already in progress.
    /// </summary>
    public int RestartInProgress;
}

public struct QueuedPacket
{
    public IpcPacket packet;
    public int destinationPort;
}
