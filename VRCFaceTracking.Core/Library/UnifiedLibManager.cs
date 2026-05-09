using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using VRCFaceTracking.Core.Services;
using VRCFaceTracking.Core.Contracts.Services;
using VRCFaceTracking.Core.Sandboxing;
using VRCFaceTracking.Core.Sandboxing.IPC;

namespace VRCFaceTracking.Core.Library;

public class UnifiedLibManager : ILibManager
{
    private const int SandboxedUpdateCadenceMs = 1;
    private static readonly TimeSpan PushModuleKickThreshold = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan PushModuleRestartThreshold = TimeSpan.FromMilliseconds(1000);
    private static readonly TimeSpan PushModuleWatchdogPeriod = TimeSpan.FromMilliseconds(100);
    #region Logger
    private readonly ILogger<UnifiedLibManager> _logger;
    private readonly ILogger _moduleLogger;
    private readonly ILoggerFactory _loggerFactory;
    #endregion

    #region Observables
    public ObservableCollection<ModuleMetadataInternal> LoadedModulesMetadata { get; set; }
    private bool _hasInitializedAtLeastOneModule = false;
    private readonly IDispatcherService _dispatcherService;
    #endregion

    #region Statuses
    public static ModuleState EyeStatus { get; private set; }
    public static ModuleState ExpressionStatus { get; private set; }
    #endregion

    #region Modules

    private List<Assembly> AvailableModules { get; set; }
    private readonly List<ModuleRuntimeInfo> _moduleThreads = new();
    private readonly IModuleDataService _moduleDataService;
    private CancellationTokenSource? _sandboxWatchdogCts;
    private Thread? _sandboxWatchdogThread;
    private readonly Dictionary<int, int> _replyUpdateCounts = new();
    private readonly Dictionary<int, long> _replyUpdateLogTimestamps = new();

    private string _sandboxProcessPath { get; set; }
    private List<ModuleRuntimeInfo> AvailableSandboxModules = new ();
    #endregion

    #region Thread
    private Thread _initializeWorker;
    private static VrcftSandboxServer _sandboxServer;
    #endregion
    
    public UnifiedLibManager(ILoggerFactory factory, IDispatcherService dispatcherService, IModuleDataService moduleDataService)
    {
        _loggerFactory = factory;
        _logger = factory.CreateLogger<UnifiedLibManager>();
        _moduleLogger = factory.CreateLogger("\0VRCFT\0");
        _dispatcherService = dispatcherService;
        _moduleDataService = moduleDataService;

        LoadedModulesMetadata = new ObservableCollection<ModuleMetadataInternal>();
        var sandboxProcessFileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "VRCFaceTracking.ModuleProcess.exe"
            : "VRCFaceTracking.ModuleProcess";
        _sandboxProcessPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, sandboxProcessFileName));
        if ( !File.Exists(_sandboxProcessPath) )
        {
            // @TODO: Better error handling
            throw new FileNotFoundException($"Failed to find sandbox process at \"{_sandboxProcessPath}\"!");
        }

        // @TODO: Kill any lingering sub-modules to eliminate any conflicts
    }

    private void StartSandboxWatchdog()
    {
        if (_sandboxWatchdogThread?.IsAlive ?? false)
            return;

        _sandboxWatchdogCts = new CancellationTokenSource();
        _sandboxWatchdogThread = new Thread(() =>
        {
            while (!_sandboxWatchdogCts.IsCancellationRequested)
            {
                try
                {
                    MonitorSandboxModules();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Sandbox watchdog iteration failed.");
                }

                _sandboxWatchdogCts.Token.WaitHandle.WaitOne(PushModuleWatchdogPeriod);
            }
        })
        {
            IsBackground = true,
            Name = "VRCFT Sandbox Watchdog"
        };
        _sandboxWatchdogThread.Start();
    }

    private void MonitorSandboxModules()
    {
        if (_sandboxServer == null)
            return;

        List<ModuleRuntimeInfo> snapshot;
        lock (AvailableSandboxModules)
        {
            snapshot = AvailableSandboxModules.ToList();
        }

        foreach (var module in snapshot)
        {
            if (!IsSandboxProcessAlive(module))
            {
                HandleExitedSandboxModule(module, snapshot.Count);
                continue;
            }

            if (!module.IsActive ||
                !module.PrefersPushUpdates ||
                module.SandboxProcessPort <= 0 ||
                !(module.ModuleInformation?.Active ?? false))
            {
                continue;
            }

            var staleFor = Stopwatch.GetElapsedTime(Interlocked.Read(ref module.LastReplyUpdateTimestamp));
            if (staleFor < PushModuleKickThreshold)
            {
                if (Volatile.Read(ref module.StaleKickCount) != 0)
                    Interlocked.Exchange(ref module.StaleKickCount, 0);
                continue;
            }

            if (staleFor >= PushModuleRestartThreshold)
            {
                if (Interlocked.CompareExchange(ref module.RestartInProgress, 1, 0) != 0)
                    continue;

                var restartAttempt = Interlocked.Increment(ref module.RestartCount);
                var moduleName = module.ModuleInformation?.Name ?? module.ModuleClassName ?? "Unknown";
                _logger.LogWarning(
                    "Sandbox module {module} pid={pid} port={port} stopped producing ReplyUpdate packets for {elapsedMs} ms. Restarting module (attempt {attempt}). activeEntries={entryCount}",
                    moduleName,
                    module.SandboxProcessPID,
                    module.SandboxProcessPort,
                    staleFor.TotalMilliseconds,
                    restartAttempt,
                    snapshot.Count);

                ThreadPool.QueueUserWorkItem(_ => RestartSandboxModule(module));
                continue;
            }

            var kickCount = Interlocked.Increment(ref module.StaleKickCount);
            if (kickCount == 1 || kickCount % 20 == 0)
            {
                var moduleName = module.ModuleInformation?.Name ?? module.ModuleClassName ?? "Unknown";
                _logger.LogWarning(
                    "Sandbox module {module} pid={pid} port={port} has not produced ReplyUpdate packets for {elapsedMs} ms. Sending fallback EventUpdate kick. activeEntries={entryCount}",
                    moduleName,
                    module.SandboxProcessPID,
                    module.SandboxProcessPort,
                    staleFor.TotalMilliseconds,
                    snapshot.Count);
            }

            _sandboxServer.SendData(new EventUpdatePacket(), module.SandboxProcessPort);
        }
    }

    private void HandleExitedSandboxModule(ModuleRuntimeInfo module, int activeEntryCount)
    {
        var moduleName = module.ModuleInformation?.Name ?? module.ModuleClassName ?? "Unknown";
        var exitCodeText = TryGetSandboxExitCode(module, out var exitCode)
            ? exitCode.ToString()
            : "unknown";
        var isShuttingDown = _sandboxWatchdogCts?.IsCancellationRequested == true;
        var canRestart = !isShuttingDown &&
                         module.SandboxProcessPort > 0 &&
                         !string.IsNullOrWhiteSpace(module.SandboxModulePath);

        if (!canRestart)
        {
            CleanupExitedSandboxModule(module);
            _logger.LogWarning(
                "Pruning exited sandbox module entry for {module}. pid={pid} port={port} exitCode={exitCode} shuttingDown={shuttingDown} isActive={isActive} moduleActive={moduleActive} status={status}",
                moduleName,
                module.SandboxProcessPID,
                module.SandboxProcessPort,
                exitCodeText,
                isShuttingDown,
                module.IsActive,
                module.ModuleInformation?.Active,
                module.Status);
            return;
        }

        if (Interlocked.CompareExchange(ref module.RestartInProgress, 1, 0) != 0)
            return;

        var restartAttempt = Interlocked.Increment(ref module.RestartCount);
        _logger.LogWarning(
            "Sandbox module {module} pid={pid} port={port} exited unexpectedly (exitCode={exitCode}). Restarting module (attempt {attempt}). activeEntries={entryCount} isActive={isActive} moduleActive={moduleActive} status={status}",
            moduleName,
            module.SandboxProcessPID,
            module.SandboxProcessPort,
            exitCodeText,
            restartAttempt,
            activeEntryCount,
            module.IsActive,
            module.ModuleInformation?.Active,
            module.Status);

        ThreadPool.QueueUserWorkItem(_ => RestartSandboxModule(module));
    }

    private void CleanupExitedSandboxModule(ModuleRuntimeInfo module)
    {
        ReleaseModuleTrackingClaims(module);
        lock (AvailableSandboxModules)
        {
            AvailableSandboxModules.Remove(module);
        }

        RemoveLoadedModuleMetadata(module.ModuleInformation?.Name ?? module.ModuleClassName ?? "Unknown");
    }

    private static bool TryGetSandboxExitCode(ModuleRuntimeInfo module, out int exitCode)
    {
        exitCode = default;
        try
        {
            if (module?.Process == null)
                return false;

            module.Process.Refresh();
            if (!module.Process.HasExited)
                return false;

            exitCode = module.Process.ExitCode;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void RemoveLoadedModuleMetadata(string moduleName)
    {
        if (string.IsNullOrWhiteSpace(moduleName))
            return;

        _dispatcherService.Run(() =>
        {
            for (var i = LoadedModulesMetadata.Count - 1; i >= 0; i--)
            {
                if (!string.Equals(LoadedModulesMetadata[i].Name, moduleName, StringComparison.Ordinal))
                    continue;

                LoadedModulesMetadata.RemoveAt(i);
            }
        });
    }

    private static bool IsSandboxProcessAlive(ModuleRuntimeInfo module)
    {
        try
        {
            if (module?.Process == null)
                return false;

            module.Process.Refresh();
            return !module.Process.HasExited;
        }
        catch
        {
            return false;
        }
    }

    private void RestartSandboxModule(ModuleRuntimeInfo module)
    {
        try
        {
            var modulePath = module.SandboxModulePath;
            var moduleName = module.ModuleInformation?.Name ?? module.ModuleClassName ?? "Unknown";

            var teardownSuccess = false;
            try
            {
                teardownSuccess = TeardownModuleSandboxed(module, gracefulRequest: false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed tearing down stale sandbox module {module}.", moduleName);
            }

            KillSandboxProcess(module);

            lock (AvailableSandboxModules)
            {
                AvailableSandboxModules.Remove(module);
            }

            RemoveLoadedModuleMetadata(moduleName);

            if (!teardownSuccess)
                _logger.LogWarning("Sandbox module {module} did not tear down cleanly before restart.", moduleName);

            InitialiseSandboxesBaseOnPaths([modulePath]);
        }
        finally
        {
            Interlocked.Exchange(ref module.LastReplyUpdateTimestamp, Stopwatch.GetTimestamp());
            Interlocked.Exchange(ref module.StaleKickCount, 0);
            Interlocked.Exchange(ref module.RestartInProgress, 0);
        }
    }

    private void KillSandboxProcess(ModuleRuntimeInfo module)
    {
        try
        {
            Process? proc = module.Process;
            if (proc == null && module.SandboxProcessPID > 0)
                proc = Process.GetProcessById(module.SandboxProcessPID);

            if (proc == null)
                return;

            proc.Refresh();
            if (proc.HasExited)
                return;

            _logger.LogWarning("Killing lingering sandbox process {pid}.", proc.Id);
            proc.Kill(entireProcessTree: true);
            proc.WaitForExit(2000);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed killing lingering sandbox process {pid}.", module.SandboxProcessPID);
        }
    }

    public void Initialize()
    {
        StartSandboxWatchdog();
        LoadedModulesMetadata.Clear();
        LoadedModulesMetadata.Add(new ModuleMetadataInternal
        { 
            Active = false,
            Name = "Initializing Modules..."
        });

        // Spawn sandbox server if it's null
        if (_sandboxServer == null )
        {
            // @TODO: Figure out an elegant way to ask the GUI for the ports the user assigned to the OSCTarget.
            int[] reservedPorts = new int[2] { 9000, 9001 };
            _sandboxServer = new VrcftSandboxServer(_loggerFactory, reservedPorts);
            _sandboxServer.OnPacketReceived += (in IpcPacket packet, in int port) =>
            {
                // Get sandbox module internal index
                int moduleIndex = -1;
                for ( int i = 0; i < AvailableSandboxModules.Count; i++ )
                {
                    if ( AvailableSandboxModules[i].SandboxProcessPort == port )
                    {
                        moduleIndex = i;
                        break;
                    }
                }

                switch ( packet.GetPacketType() )
                {
                    // @TODO: Move these all into methods to make the code easier to maintain
                    case IpcPacket.PacketType.Handshake:
                        {
                            // Look for the PID in the added modules list
                            var pkt = (HandshakePacket) packet;
                            lock ( AvailableSandboxModules )
                            {
                                bool pidRegistered = false;
                                
                                for ( int i = 0; i < AvailableSandboxModules.Count; i++ )
                                {
                                    if ( AvailableSandboxModules[i].SandboxProcessPID == pkt.PID )
                                    {
                                        var structCopy = AvailableSandboxModules[i];
                                        structCopy.SandboxProcessPort = port;
                                        AvailableSandboxModules[i] = structCopy;

                                        _logger.LogInformation("Initializing {module}...", AvailableSandboxModules[i].ModuleClassName.ToString());
                                        AttemptSandboxedModuleInitialize(AvailableSandboxModules[i]);
                                        pidRegistered = true;

                                        break;
                                    }
                                }

                                if ( pidRegistered == false )
                                {
                                    Process sandboxProcess = Process.GetProcessById(pkt.PID);

                                    ModuleRuntimeInfo runtimeInfo = new ModuleRuntimeInfo()
                                    {
                                        SandboxProcessPID   = pkt.PID,
                                        SandboxProcessPort  = port,
                                        SandboxModulePath   = pkt.ModulePath,
                                        IsActive            = true,
                                        Process             = sandboxProcess,
                                        ModuleClassName     = Path.GetFileNameWithoutExtension(pkt.ModulePath),
                                        ModuleInformation   = new (),
                                        EventBus            = new (),
                                    };
                                    AvailableSandboxModules.Add(runtimeInfo);

                                    _logger.LogInformation("Initializing {module}...", runtimeInfo.ModuleClassName);
                                    AttemptSandboxedModuleInitialize(runtimeInfo);
                                    pidRegistered = true;
                                }
                            }
                            break;
                        }

                    case IpcPacket.PacketType.EventLog:
                        {
                            EventLogPacket eventLogPacket = (EventLogPacket) packet;
                            _moduleLogger.Log(eventLogPacket.LogLevel, eventLogPacket.Message);
                            break;
                        }

                    case IpcPacket.PacketType.ReplyGetSupported:
                        {
                            // We now know whether or not the module supports face or eye tracking
                            ReplySupportedPacket replySupportedPacket = (ReplySupportedPacket) packet;

                            AvailableSandboxModules[moduleIndex].SupportsEyeTracking        = AvailableSandboxModules[moduleIndex].SupportsEyeTracking && replySupportedPacket.eyeAvailable;
                            AvailableSandboxModules[moduleIndex].SupportsExpressionTracking = AvailableSandboxModules[moduleIndex].SupportsExpressionTracking && replySupportedPacket.expressionAvailable;

                            // Now tell it to initialise
                            EventInitPacket eventInitPacket = new EventInitPacket()
                            {
                                expressionAvailable     = ExpressionStatus == ModuleState.Uninitialized,
                                eyeAvailable            = EyeStatus == ModuleState.Uninitialized,
                            };
                            _logger.LogInformation("Got supported for module {module}. Expr: {} Eye: {}...",
                                AvailableSandboxModules[moduleIndex].ModuleClassName,
                                eventInitPacket.expressionAvailable,
                                eventInitPacket.eyeAvailable);
                            _sandboxServer.SendData(eventInitPacket, port);
                            break;
                        }

                    case IpcPacket.PacketType.ReplyInit:
                        {
                            ReplyInitPacket replyInitPacket = (ReplyInitPacket) packet;
                            AvailableSandboxModules[moduleIndex].ModuleInformation.Name = replyInitPacket.ModuleInformationName;

                            // Update support variables
                            AvailableSandboxModules[moduleIndex].SupportsEyeTracking        = AvailableSandboxModules[moduleIndex].SupportsEyeTracking && replyInitPacket.eyeSuccess;
                            AvailableSandboxModules[moduleIndex].SupportsExpressionTracking = AvailableSandboxModules[moduleIndex].SupportsExpressionTracking && replyInitPacket.expressionSuccess;
                            AvailableSandboxModules[moduleIndex].PrefersPushUpdates         = replyInitPacket.prefersPushUpdates;
                            Interlocked.Exchange(ref AvailableSandboxModules[moduleIndex].LastReplyUpdateTimestamp, Stopwatch.GetTimestamp());
                            Interlocked.Exchange(ref AvailableSandboxModules[moduleIndex].StaleKickCount, 0);
                            Interlocked.Exchange(ref AvailableSandboxModules[moduleIndex].RestartInProgress, 0);

                            _logger.LogInformation("Got init for module {module}. Eye: {eye} Expr: {expr}...",
                                AvailableSandboxModules[moduleIndex].ModuleClassName,
                                replyInitPacket.eyeSuccess,
                                replyInitPacket.eyeSuccess);

                            // Skip any modules that don't succeed, otherwise set UnifiedLib to have these states active and add module to module list.
                            if ( !replyInitPacket.eyeSuccess && !replyInitPacket.expressionSuccess )
                            {
                                break;
                            }

                            int portCopy = port; // So that we can use it in the lambda method
                            AvailableSandboxModules[moduleIndex].ModuleInformation.OnActiveChange = (state) =>
                            {
                                AvailableSandboxModules[moduleIndex].Status = state ? ModuleState.Active : ModuleState.Idle;

                                EventStatusUpdatePacket statusUpdatePkt = new EventStatusUpdatePacket();
                                statusUpdatePkt.ModuleState = AvailableSandboxModules[moduleIndex].Status;
                                _sandboxServer.SendData(statusUpdatePkt, portCopy);
                            };

                            EyeStatus           = replyInitPacket.eyeSuccess        ? ModuleState.Active : ModuleState.Uninitialized;
                            ExpressionStatus    = replyInitPacket.expressionSuccess ? ModuleState.Active : ModuleState.Uninitialized;

                            AvailableSandboxModules[moduleIndex].ModuleInformation.Active           = true;
                            AvailableSandboxModules[moduleIndex].ModuleInformation.UsingEye         = !AvailableSandboxModules.Any(m => m.ModuleInformation.UsingEye) && replyInitPacket.eyeSuccess;
                            AvailableSandboxModules[moduleIndex].ModuleInformation.UsingExpression  = !AvailableSandboxModules.Any(m => m.ModuleInformation.UsingExpression) && replyInitPacket.expressionSuccess;
                            AvailableSandboxModules[moduleIndex].ModuleInformation.StaticImages     = replyInitPacket.IconDataStreams;
                            if (!replyInitPacket.prefersPushUpdates)
                                EnsureModuleThreadStartedSandboxed(AvailableSandboxModules[moduleIndex]);

                            _dispatcherService.Run(() => {

                                // Check if the module is already loaded on the user-facing side. If so, overwrite with the new module if it's unloaded
                                var isModuleLoaded = false;
                                for ( var i = 0; i < LoadedModulesMetadata.Count; i++ )
                                {
                                    // Look for modules with the same name
                                    if ( LoadedModulesMetadata[i].Name == AvailableSandboxModules[moduleIndex].ModuleInformation.Name )
                                    {
                                        // Update module info
                                        LoadedModulesMetadata[i] = AvailableSandboxModules[moduleIndex].ModuleInformation;
                                        isModuleLoaded = true;
                                        break;
                                    }
                                }

                                // Add it to list if it was never loaded
                                if ( isModuleLoaded == false )
                                {
                                    LoadedModulesMetadata.Add(AvailableSandboxModules[moduleIndex].ModuleInformation);
                                }

                                if ( AvailableSandboxModules.Count == 0 )
                                {
                                    _logger.LogWarning("No modules loaded.");
                                    LoadedModulesMetadata.Clear();
                                    LoadedModulesMetadata.Add(new ModuleMetadataInternal
                                    {
                                        Active = false,
                                        Name = "No Modules Loaded"
                                    });
                                }
                                else
                                {
                                    // Remove our dummy module
                                    if ( LoadedModulesMetadata.Count > 0 &&
                                        LoadedModulesMetadata[0].Active == false &&
                                           (LoadedModulesMetadata[0].Name == "No Modules Loaded" ||
                                            LoadedModulesMetadata[0].Name == "Initializing Modules..." ))
                                    {
                                        LoadedModulesMetadata.RemoveAt(0);
                                    }

                                    // foreach ( var pair in _moduleThreads )
                                    {
                                        if ( AvailableSandboxModules[moduleIndex].ModuleInformation.Active )
                                        {
                                            _logger.LogInformation("Tracking initialized via {module}", AvailableSandboxModules[moduleIndex].ModuleClassName.ToString());
                                        }
                                    }
                                }
                            });

                            break;
                        }
                    case IpcPacket.PacketType.ReplyUpdate:
                        {
                            ReplyUpdatePacket replyUpdatePacket = (ReplyUpdatePacket) packet;
                            Interlocked.Exchange(ref AvailableSandboxModules[moduleIndex].LastReplyUpdateTimestamp, Stopwatch.GetTimestamp());
                            Interlocked.Exchange(ref AvailableSandboxModules[moduleIndex].StaleKickCount, 0);
                            var replyCount = _replyUpdateCounts.TryGetValue(moduleIndex, out var existingReplyCount)
                                ? existingReplyCount + 1
                                : 1;
                            _replyUpdateCounts[moduleIndex] = replyCount;
                            if (!_replyUpdateLogTimestamps.TryGetValue(moduleIndex, out var lastReplyLogTs))
                            {
                                _replyUpdateLogTimestamps[moduleIndex] = Stopwatch.GetTimestamp();
                                _logger.LogInformation(
                                    "ReplyUpdate flow started for {module}. pid={pid} port={port} count={count} status={status} usingEye={usingEye} usingExpr={usingExpr}",
                                    AvailableSandboxModules[moduleIndex].ModuleInformation?.Name ?? AvailableSandboxModules[moduleIndex].ModuleClassName ?? "Unknown",
                                    AvailableSandboxModules[moduleIndex].SandboxProcessPID,
                                    AvailableSandboxModules[moduleIndex].SandboxProcessPort,
                                    replyCount,
                                    AvailableSandboxModules[moduleIndex].Status,
                                    AvailableSandboxModules[moduleIndex].ModuleInformation?.UsingEye,
                                    AvailableSandboxModules[moduleIndex].ModuleInformation?.UsingExpression);
                            }
                            else if (Stopwatch.GetElapsedTime(lastReplyLogTs) >= TimeSpan.FromSeconds(5))
                            {
                                _replyUpdateLogTimestamps[moduleIndex] = Stopwatch.GetTimestamp();
                                _logger.LogInformation(
                                    "ReplyUpdate stats for {module}: pid={pid} port={port} count={count} status={status} usingEye={usingEye} usingExpr={usingExpr}",
                                    AvailableSandboxModules[moduleIndex].ModuleInformation?.Name ?? AvailableSandboxModules[moduleIndex].ModuleClassName ?? "Unknown",
                                    AvailableSandboxModules[moduleIndex].SandboxProcessPID,
                                    AvailableSandboxModules[moduleIndex].SandboxProcessPort,
                                    replyCount,
                                    AvailableSandboxModules[moduleIndex].Status,
                                    AvailableSandboxModules[moduleIndex].ModuleInformation?.UsingEye,
                                    AvailableSandboxModules[moduleIndex].ModuleInformation?.UsingExpression);
                            }

                            if ( AvailableSandboxModules[moduleIndex].Status == ModuleState.Active && AvailableSandboxModules[moduleIndex].ModuleInformation.Active )
                            {
                                if ( AvailableSandboxModules[moduleIndex].ModuleInformation.UsingEye )
                                {
                                    replyUpdatePacket.UpdateGlobalEyeState();
                                }
                                if ( AvailableSandboxModules[moduleIndex].ModuleInformation.UsingExpression )
                                {
                                    replyUpdatePacket.UpdateGlobalExpressionState();
                                }
                                replyUpdatePacket.UpdateHeadState();
                                ParameterSenderService.SignalPendingUpdate();
                            }

                            break;
                        }
                }
            };
        }

        // Start Initialization
        _initializeWorker = new Thread(() =>
        {
            // Kill lingering threads
            TeardownAllAndResetAsync();

            // Find all modules
            var modules = _moduleDataService.GetInstalledModules().Concat(_moduleDataService.GetLegacyModules());
            var modulePaths = modules.Select(m => m.AssemblyLoadPath);

            // Load all modules
            AvailableSandboxModules.Clear();
            InitialiseSandboxesBaseOnPaths(modulePaths.ToArray());

            if ( AvailableSandboxModules != null && AvailableSandboxModules.Count > 0 )
            {
                _logger.LogDebug("Initializing requested runtimes...");
            }
            else
            {
                _dispatcherService.Run(() =>
                {
                    LoadedModulesMetadata.Clear();
                    LoadedModulesMetadata.Add(new ModuleMetadataInternal
                    {
                        Active = false,
                        Name = "No Modules Loaded"
                    });
                });
                _logger.LogWarning("No modules loaded.");
            }

        });
        _logger.LogInformation("Starting initialization tracking");
        _initializeWorker.Start();
    }

    private void InitialiseSandboxesBaseOnPaths(IEnumerable<string> paths)
    {
        foreach ( var dll in paths )
        {
            try
            {
                // Start subprocess
                var sandboxProcess  = Process.Start(new ProcessStartInfo(
                    _sandboxProcessPath, $"--port {_sandboxServer.Port} --module-path \"{dll}\""
                )
                {
#if !DEBUG
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
#else
                    // In debug mode we connect stdout and stderr
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
#endif
                });

#if DEBUG
                // Start a thread to copy stderr and stdout to debug
                new Thread(() =>
                {
                    string output = sandboxProcess.StandardOutput.ReadToEnd();
                    output = output + sandboxProcess.StandardError.ReadToEnd();
                    sandboxProcess.WaitForExit();
                    Debug.WriteLine(output);
                }).Start();
#endif

                var pid             = sandboxProcess.Id;

                // Add the module info into the loaded list
                ModuleRuntimeInfo runtimeInfo = new ModuleRuntimeInfo()
                {
                    SandboxProcessPID   = pid,
                    SandboxProcessPort  = -1,
                    SandboxModulePath   = dll,
                    IsActive            = true,
                    Process             = sandboxProcess,
                    ModuleClassName     = Path.GetFileNameWithoutExtension(dll),
                    ModuleInformation   = new (),
                    EventBus            = new ()
                };
                lock ( AvailableSandboxModules )
                {
                    _logger.LogDebug("Started sandbox process with dll {dllPath}", dll);
                    AvailableSandboxModules.Add(runtimeInfo);
                }
            }
            catch ( Exception e )
            {
                _logger.LogWarning("{error} Failed to start sandbox process for {path}. Skipping...", e.Message, dll);
            }
        }
    }
    
    private void EnsureModuleThreadStartedSandboxed(ModuleRuntimeInfo module)
    {
        if (_moduleThreads.Any(pair =>
            ( pair.SandboxProcessPID    == module.SandboxProcessPID ) &&
            ( pair.SandboxProcessPort   == module.SandboxProcessPort )
        ))
        {
            return;
        }

        int port = module.SandboxProcessPort;

        var cts = new CancellationTokenSource();
        var thread = new Thread(() =>
        {
            _logger.LogDebug("Starting thread for {module}", module.GetType().Name);
            var updatePacket = new EventUpdatePacket();
            while (!cts.IsCancellationRequested)
            {
                Thread.Sleep(SandboxedUpdateCadenceMs);
                _sandboxServer.SendData(updatePacket, port);
            }
            _logger.LogDebug("Thread for {module} ended", module.GetType().Name);
        });
        thread.Start();
        module.UpdateCancellationToken = cts;
        module.UpdateThread = thread;

        _moduleThreads.Add(module);
    }

    private void AttemptSandboxedModuleInitialize(ModuleRuntimeInfo module)
    {
        // Tell the sandbox to call the initialize function on the module
        var eventGetSupportedPacket = new EventInitGetSupported();

        // If PID is valid and we know which port the sandbox process is running on
        if ( module.SandboxProcessPID != -1 && module.SandboxProcessPort > 0 )
        {
            _sandboxServer.SendData(eventGetSupportedPacket, module.SandboxProcessPort);
        }
        else
        {
            // Queue the packet so that we send it after we know which process the sandbox process is running on
            QueuedPacket queuedPacket = new QueuedPacket()
            {
                packet = eventGetSupportedPacket,
                destinationPort = module.SandboxProcessPort
            };
            module.EventBus.Enqueue(queuedPacket);
        }
    }

    private bool TeardownModuleSandboxed(ModuleRuntimeInfo module, bool gracefulRequest = true)
    {
        _logger.LogInformation("Tearing down {module} ", module.ModuleClassName);

        ReleaseModuleTrackingClaims(module);

        if (gracefulRequest)
        {
            // Send a message to the module sub-process
            var eventTeardownPacket = new EventTeardownPacket();
            try
            {
                _sandboxServer.SendData(eventTeardownPacket, module.SandboxProcessPort);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed sending teardown packet to sandbox module {module}. Forcing process shutdown.", module.ModuleClassName);
            }
        }

        // Kill the update thread
        module.UpdateCancellationToken?.Cancel();
        // Give the module 100ms to kill itself
        Thread.Sleep(100);

        if (module.Process == null)
            return true;

        // Only bother tearing down a module if it's actually shutdown
        try
        {
            module.Process.Refresh();
            if (!module.Process.HasExited)
            {
                _logger.LogDebug("Module process has not yet exited");
                if (!module.Process.WaitForExit(200))
                {
                    _logger.LogDebug("Module {id} didn't exit gracefully. Forcing kill...", module.Process.Id);
                    module.Process.Kill(entireProcessTree: true);
                    if (!module.Process.WaitForExit(2000))
                    {
                        // on windows we can use taskkill /F /T /PID {procId} to force kill a process very aggressively. this has a higher success rate than process.kill!
                        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        {
                            using var killer = Process.Start(new ProcessStartInfo
                            {
                                FileName = "taskkill",
                                Arguments = $"/F /T /PID {module.Process.Id}",
                                CreateNoWindow = true,
                                UseShellExecute = false
                            });
                            killer?.WaitForExit(2000);
                        }
                        else
                        {
                            _logger.LogCritical("Process {id} is a zombie or stuck in Kernel I/O. Manual intervention required.", module.Process.Id);
                        }

                        module.Process.Refresh();
                        if (!module.Process.HasExited)
                            return false;
                    }
                }
            }
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            _logger.LogError(ex, "Tried killing process with PID {pid}.", module.Process.Id);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Tried killing process with PID {pid}.", module.Process.Id);
            return false;
        }

        if (module.UpdateThread?.IsAlive ?? false)
        {
            // Edge case, we wait for the thread to finish before unloading the assembly
            var moduleName = module.ModuleInformation?.Name ?? module.ModuleClassName ?? "Unknown";
            _logger.LogDebug("Waiting for {module}'s thread to join...", moduleName);
            module.UpdateThread?.Join(500);
        }

        return true;
    }

    private void ReleaseModuleTrackingClaims(ModuleRuntimeInfo module)
    {
        var hadEye = module.ModuleInformation?.UsingEye == true;
        var hadExpression = module.ModuleInformation?.UsingExpression == true;

        if (hadEye)
            EyeStatus = ModuleState.Uninitialized;

        if (hadExpression)
            ExpressionStatus = ModuleState.Uninitialized;

        if (module.ModuleInformation != null)
        {
            module.ModuleInformation.Active = false;
            module.ModuleInformation.UsingEye = false;
            module.ModuleInformation.UsingExpression = false;
        }

        module.Status = ModuleState.Uninitialized;
        module.IsActive = false;

        if (module.UpdateThread != null || module.UpdateCancellationToken != null)
        {
            _moduleThreads.RemoveAll(pair =>
                pair.SandboxProcessPID == module.SandboxProcessPID &&
                pair.SandboxProcessPort == module.SandboxProcessPort);
        }
    }

    // Signal all active modules to gracefully shut down their respective runtimes
    public void TeardownAllAndResetAsync()
    {
        _logger.LogInformation("Tearing down all modules...");

        foreach ( var module in _moduleThreads )
        {
            var success = false;
            if (module == null || (module.Process?.HasExited ?? true))
                continue;
            try
            {
                success = TeardownModuleSandboxed(module);
            } finally
            {
                if ( !success )
                {
                    _logger.LogWarning($"Module: {module.Module.ModuleInformation.Name} failed to shut down. Killing its thread.");
                    module.UpdateThread.Interrupt();
                }
            }
        }

        _moduleThreads.Clear();

        foreach ( var module in AvailableSandboxModules )
        {
            var success = false;
            if (module == null || (module.Process?.HasExited ?? true)) // c# objects may be null, use null coalesce to detect if a module has been destroyed but we have a lingering ref to it
                continue;
            try
            {
                success = TeardownModuleSandboxed(module);
            } finally
            {
                if ( !success )
                {
                    var moduleName = module.ModuleInformation?.Name ?? module.ModuleClassName ?? "Unknown";
                    _logger.LogWarning($"Module: {moduleName} failed to shut down. Killing its thread.");
                    module.UpdateThread?.Interrupt();
                }
            }
        }

        AvailableSandboxModules.Clear();

        EyeStatus = ModuleState.Uninitialized;
        ExpressionStatus = ModuleState.Uninitialized;
    }
}
