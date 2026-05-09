using System.CommandLine;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VRCFaceTracking.Core.Params.Data;
using VRCFaceTracking.Core.Params.Expressions;
using VRCFaceTracking.Core.Sandboxing;
using VRCFaceTracking.Core.Sandboxing.IPC;

namespace VRCFaceTracking.ModuleProcess;

public class ModuleProcessMain
{
    // How long in seconds we should wait for a connection to be established before giving up
    private const double CONNECTION_TIMEOUT = 60.0; // This is long because some modules like the Vive Facial Tracker software can take a long time to initialise
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(CONNECTION_TIMEOUT);
    private static readonly TimeSpan PushUpdateWatchdog = TimeSpan.FromMilliseconds(25);
    private static bool WaitForPackets = true;
    public static ModuleAssembly DefModuleAssembly;
    public static ILoggerFactory? LoggerFactory;
    public static ILogger<ModuleProcessMain> Logger;
    public static VrcftSandboxClient Client;
    public static CancellationTokenSource cts = new();

    private static readonly ConcurrentQueue<IpcPacket> _packetsToSend = new();
    private static readonly AutoResetEvent _packetsQueued = new(false);
    private static int _replyUpdateQueued;
    private static long _lastUpdateActivityTimestamp = Stopwatch.GetTimestamp();
    private static long _lastInboundPacketTimestamp = Stopwatch.GetTimestamp();
    private static int _pushWatchdogFireCount;
    private static int _replyUpdateEnqueueCount;
    private static long _replyUpdateEnqueueLogTimestamp = Stopwatch.GetTimestamp();
    private static int _moduleInitialized;

    private static void MarkUpdateActivity()
    {
        Interlocked.Exchange(ref _lastUpdateActivityTimestamp, Stopwatch.GetTimestamp());
    }

    private static void MarkInboundPacket()
    {
        Interlocked.Exchange(ref _lastInboundPacketTimestamp, Stopwatch.GetTimestamp());
    }

    private static void EnqueuePacket(IpcPacket packet)
    {
        if (packet.GetPacketType() == IpcPacket.PacketType.ReplyUpdate)
        {
            if (Interlocked.Exchange(ref _replyUpdateQueued, 1) == 1)
                return;

            MarkUpdateActivity();
            var enqueueCount = Interlocked.Increment(ref _replyUpdateEnqueueCount);
            var now = Stopwatch.GetTimestamp();
            if (enqueueCount == 1 || Stopwatch.GetElapsedTime(Interlocked.Read(ref _replyUpdateEnqueueLogTimestamp)) >= TimeSpan.FromSeconds(5))
            {
                Interlocked.Exchange(ref _replyUpdateEnqueueLogTimestamp, now);
                Logger?.LogInformation("ReplyUpdate enqueue stats: count={count} connected={connected}", enqueueCount, Client?.IsConnected);
            }
        }

        _packetsToSend.Enqueue(packet);
        _packetsQueued.Set();
    }

    private static void QueueImmediateUpdate()
    {
        EnqueuePacket(new ReplyUpdatePacket());
    }

    private static bool ShouldKickPushWatchdog()
    {
        if (DefModuleAssembly?.TrackingModule?.SupportsPushUpdates != true)
            return false;

        if (DefModuleAssembly._updateCts?.IsCancellationRequested == true)
            return false;

        return Stopwatch.GetElapsedTime(Interlocked.Read(ref _lastUpdateActivityTimestamp)) >= PushUpdateWatchdog;
    }

    private static bool IsWaitingForInitialHostTraffic()
    {
        if (Client == null || !Client.IsConnected)
            return true;

        return Volatile.Read(ref _moduleInitialized) == 0;
    }

    public static int Main(string[] args)
    {
        AppDomain.CurrentDomain.ProcessExit += (sender, e) =>
        {
            Logger.LogInformation("Received SIGTERM");
            WaitForPackets = false;
            DefModuleAssembly._updateCts?.Cancel();
            cts.Cancel();
            cts.Token.WaitHandle.WaitOne(TimeSpan.FromSeconds(5));
        };
        
        try
        {
            if ( args.Length < 1 )
            {
                // Not enough arguments
                return ModuleProcessExitCodes.INVALID_ARGS;
            }

            var portOption = new Option<int?>("--port")
            {
                Description = "The UDP port the VRCFT server is running on."
            };
            var modulePathOption = new Option<string?>("--module-path")
            {
                Description = "The path to the module to load."
            };

            var rootCommand = new RootCommand("VRCFT Sandbox Module");
            rootCommand.Options.Add(portOption);
            rootCommand.Options.Add(modulePathOption);

            rootCommand.SetAction(parseResult =>
            {
                var modulePath = parseResult.GetValue(modulePathOption);
                var port = parseResult.GetValue(portOption);
                VrcftMain(modulePath!, port ?? 0);
                return 0;
            });

            return rootCommand.Parse(args).Invoke();
        }
        catch ( Exception ex )
        {
            // So that we can catch errors
            Logger.LogCritical($"{ex.Message}:\n{ex.StackTrace}");
            Logger.LogCritical($"{ex.Message}");
#if DEBUG
            Console.ReadKey();
            Console.ReadLine();
#endif
            return ModuleProcessExitCodes.EXCEPTION_CRASH;
        }
        finally
        {
            Client?.Dispose();
        }
    }

    static int VrcftMain(string modulePath, int serverPortNumber)
    {
        ServiceProvider serviceProvider = new ServiceCollection()
        .AddLogging((loggingBuilder) => loggingBuilder
                .ClearProviders()
                .AddDebug()
                .AddConsole()
                // .AddSentry(o =>
                //     o.Dsn =
                //     "https://444b0799dd2b670efa85d866c8c12134@o4506152235237376.ingest.us.sentry.io/4506152246575104")
                .AddProvider(new ProxyLoggerProvider())
            )
        .BuildServiceProvider();

        LoggerFactory = serviceProvider.GetService<ILoggerFactory>();
        Logger = LoggerFactory.CreateLogger<ModuleProcessMain>();
        TryElevateRealtimePriority();
        Interlocked.Exchange(ref _lastInboundPacketTimestamp, Stopwatch.GetTimestamp());
        Volatile.Write(ref _moduleInitialized, 0);

        // A module process will connect to a given port number first. We try connecting to the server for 30 seconds, then give up, returning an error code in the process.
        Client = new VrcftSandboxClient(serverPortNumber, LoggerFactory);

        // Bind the log function so that we can forward log messages to VRCFT's main process
        ProxyLogger.OnLog += (level, msg) =>
        {
            var pkt = new EventLogPacket(level, msg);
            Client.SendData(pkt);
        };

        // Try loading the module
        DefModuleAssembly = new ModuleAssembly(Logger, LoggerFactory, modulePath);
        DefModuleAssembly.TryLoadAssembly();
        if (DefModuleAssembly.TrackingModule != null)
            DefModuleAssembly.TrackingModule.RequestImmediateUpdate = QueueImmediateUpdate;

        // Initialise to invalid state
        UnifiedTracking.Data = new() {
            Eye = new()
            {
                Left = new()
                {
                    Gaze = new(0xFFFFFFFF, 0xFFFFFFFF),
                    Openness = 0xFFFFFFFF,
                    PupilDiameter_MM = 0xFFFFFFFF
                },
                Right = new()
                {
                    Gaze = new(0xFFFFFFFF, 0xFFFFFFFF),
                    Openness = 0xFFFFFFFF,
                    PupilDiameter_MM = 0xFFFFFFFF
                },
                _maxDilation = 0xFFFFFFFF,
                _minDilation = 0xFFFFFFFF,
            }
        };
        for ( int i = 0; i < ( int )UnifiedExpressions.Max + 1; i++ )
        {
            UnifiedTracking.Data.Shapes[i].Weight = 0xFFFFFFFF;
        }

        Client.OnPacketReceivedCallback += (in IpcPacket packet) => {
            MarkInboundPacket();

            // Handle packets
            switch ( packet.GetPacketType() )
            {
                case IpcPacket.PacketType.EventGetSupported:
                    {
                        var result = DefModuleAssembly.TrackingModule.Supported;
                        var pkt = new ReplySupportedPacket()
                        {
                            eyeAvailable        = result.SupportsEye,
                            expressionAvailable = result.SupportsExpression
                        };
                        EnqueuePacket(pkt);
                        break;
                    }
                case IpcPacket.PacketType.EventInit:
                    {
                        var pkt = (EventInitPacket) packet;

                        bool eyeSuccess, expressionSuccess;
                        try
                        {
                            (eyeSuccess, expressionSuccess) = DefModuleAssembly.TrackingModule.Initialize(pkt.eyeAvailable, pkt.expressionAvailable);
                        }
                        catch ( MissingMethodException )
                        {
                            Logger.LogError("{moduleName} does not properly implement ExtTrackingModule. Skipping.", DefModuleAssembly.GetType().Name);
                            return;
                        } catch ( Exception e )
                        {
                            Logger.LogError("Exception initializing {module}. Skipping. {e}", DefModuleAssembly.GetType().Name, e);
                            return;
                        }
                        
                        DefModuleAssembly._updateCts = new CancellationTokenSource();
                        Volatile.Write(ref _moduleInitialized, 1);
                        MarkUpdateActivity();
                        if (!DefModuleAssembly.TrackingModule.SupportsPushUpdates)
                        {
                            var thread = new Thread(() =>
                            {
                                while (!DefModuleAssembly._updateCts.IsCancellationRequested)
                                {
                                    DefModuleAssembly.TrackingModule.Update();
                                }
                            });
                            thread.Start();
                        }
                        
                        var pktNew = new ReplyInitPacket()
                        {
                            eyeSuccess              = eyeSuccess,
                            expressionSuccess       = expressionSuccess,
                            ModuleInformationName   = DefModuleAssembly.TrackingModule.ModuleInformation.Name,
                            IconDataStreams         = DefModuleAssembly.TrackingModule.ModuleInformation.StaticImages
                        };
                        pktNew.prefersPushUpdates = DefModuleAssembly.TrackingModule.SupportsPushUpdates;
                        EnqueuePacket(pktNew);
                        break;
                    }

                case IpcPacket.PacketType.EventTeardown:
                    {
                        Logger.LogInformation("Received Teardown packet");
                        DefModuleAssembly._updateCts?.Cancel();
                        try
                        {
                            DefModuleAssembly.TrackingModule.Teardown();
                        }
                        catch(Exception e)
                        {
                            Logger.LogWarning("Tracking module failed to cleanly shut down.");
                            Logger.LogError(e.ToString());
                        }

                        Logger.LogInformation("Cancelled Update Threads");
                        
                        // Tell VRCFT that we have shut down successfully (otherwise VRCFT will terminate this process)
                        var pkt = new ReplyTeardownPacket();
                        // Tell VRCFT we have shutdown immediately
                        Client.SendData(pkt);
                        
                        Logger.LogInformation("Sent teardown ACK");

                        // Shut down the event loop
                        Environment.Exit(ModuleProcessExitCodes.OK);
                        break;
                    }

                case IpcPacket.PacketType.EventUpdate:
                    {
                        // Logger.LogDebug("EventUpdate");
                        var pkt = new ReplyUpdatePacket();
                        EnqueuePacket(pkt);
                        break;
                    }

                case IpcPacket.PacketType.EventUpdateStatus:
                    {
                        var pkt = (EventStatusUpdatePacket) packet;
                        DefModuleAssembly.TrackingModule.Status = pkt.ModuleState;

                        break;
                    }
            }

        };
        if (OperatingSystem.IsWindows())
        {
            Core.Utils.TimeBeginPeriod(1);
        }
        
        // Start the connection
        Client.Connect(modulePath);
        Logger.LogInformation("Initializing {module}", DefModuleAssembly.Assembly.ToString());
        
        // Loop infinitely while we wait for commands
        while ( WaitForPackets && !cts.IsCancellationRequested)
        {
            if (IsWaitingForInitialHostTraffic() &&
                Stopwatch.GetElapsedTime(Interlocked.Read(ref _lastInboundPacketTimestamp)) > ConnectionTimeout)
            {
                Logger.LogWarning(
                    "Sandbox module {module} timed out waiting for initial host traffic. connected={connected} initialized={initialized} modulePath={modulePath}",
                    DefModuleAssembly?.TrackingModule?.ModuleInformation.Name ?? DefModuleAssembly?.Assembly?.GetName().Name ?? "Unknown",
                    Client?.IsConnected,
                    Volatile.Read(ref _moduleInitialized) == 1,
                    modulePath);
                Client.Close();
                return ModuleProcessExitCodes.NETWORK_CONNECTION_TIMED_OUT;
            }

            // Send packets in loop
            var sentPacket = false;
            while (_packetsToSend.TryDequeue(out IpcPacket pkt))
            {
                if (pkt == null) continue;  // Ignore your IDE. This can and will be null at some point as we're not locking
                if (pkt.GetPacketType() == IpcPacket.PacketType.ReplyUpdate)
                    Interlocked.Exchange(ref _replyUpdateQueued, 0);
                Client.SendData(pkt);
                sentPacket = true;
            }

            if (!sentPacket)
            {
                var waitTimeout = Client.IsConnected ? 10 : 50;
                WaitHandle.WaitAny([_packetsQueued, cts.Token.WaitHandle], waitTimeout);

                if (ShouldKickPushWatchdog())
                {
                    if (Interlocked.Increment(ref _pushWatchdogFireCount) == 1 || _pushWatchdogFireCount % 50 == 0)
                        Logger.LogWarning(
                            "Push update watchdog fired for {module}. Queueing fallback update. connected={connected}",
                            DefModuleAssembly?.TrackingModule?.ModuleInformation.Name ?? "Unknown",
                            Client?.IsConnected);

                    QueueImmediateUpdate();
                }
            }
        }
        
        DefModuleAssembly._updateCts?.Cancel();

        if (OperatingSystem.IsWindows())
        {
            Core.Utils.TimeEndPeriod(1);
        }

        Environment.Exit(ModuleProcessExitCodes.OK);
        return ModuleProcessExitCodes.OK;
    }

    private static void TryElevateRealtimePriority()
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            using var currentProcess = Process.GetCurrentProcess();
            currentProcess.PriorityClass = ProcessPriorityClass.AboveNormal;
        }
        catch
        {
            // Best-effort only.
        }

        try
        {
            Thread.CurrentThread.Priority = ThreadPriority.AboveNormal;
        }
        catch
        {
            // Best-effort only.
        }
    }
}
