using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VRCFaceTracking.Core.Contracts;
using VRCFaceTracking.Core.OSC;
using VRCFaceTracking.Core.Params.Data;

namespace VRCFaceTracking.Core.Services;

public class ParameterSenderService : BackgroundService
{
    private static readonly object SendQueueLock = new();
    private static readonly SemaphoreSlim PendingUpdateSignal = new(0, 1);
    private static List<OscMessage> SendQueue = new();

    private readonly ILogger<ParameterSenderService> _logger;
    private readonly OscSendService _sendService;
    private readonly UnifiedTrackingMutator _mutator; // DI side effect
    private List<OscMessage> _dispatchBuffer = new(256);
    private int _signalsThisWindow;
    private int _batchesThisWindow;
    private int _messagesThisWindow;
    private int _exceptionsThisWindow;

    public static bool AllParametersRelevantStatic
    {
        get;
        set;
    }

    public bool AllParametersRelevant
    {
        get => AllParametersRelevantStatic;
        set
        {
            if (AllParametersRelevantStatic == value) return;
            AllParametersRelevantStatic = value;
            lock (SendQueueLock)
            {
                SendQueue.Clear();
            }

            foreach (var parameter in UnifiedTracking.AllParameters)
            {
                parameter.ResetParam(Array.Empty<IParameterDefinition>());
            }
        }
    }

    public ParameterSenderService(ILogger<ParameterSenderService> logger, OscSendService sendService, UnifiedTrackingMutator mutator)
    {
        _logger = logger;
        _sendService = sendService;
        _mutator = mutator;
    }

    public static void Enqueue(OscMessage message)
    {
        lock (SendQueueLock)
        {
            SendQueue.Add(message);
        }
    }

    public static void Clear()
    {
        lock (SendQueueLock)
        {
            SendQueue.Clear();
        }
    }

    public static void SignalPendingUpdate()
    {
        try
        {
            if (PendingUpdateSignal.CurrentCount == 0)
                PendingUpdateSignal.Release();
        }
        catch (SemaphoreFullException)
        {
            // A concurrent release beat us to it. That is harmless because the loop only needs one wakeup.
        }
    }

    private async Task LogStatsAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            int queueDepth;
            lock (SendQueueLock)
            {
                queueDepth = SendQueue.Count;
            }

            var signals = Interlocked.Exchange(ref _signalsThisWindow, 0);
            var batches = Interlocked.Exchange(ref _batchesThisWindow, 0);
            var messages = Interlocked.Exchange(ref _messagesThisWindow, 0);
            var exceptions = Interlocked.Exchange(ref _exceptionsThisWindow, 0);

            _logger.LogInformation(
                "ParameterSender stats: signals={signals} batches={batches} messages={messages} queueDepth={queueDepth} exceptions={exceptions}",
                signals, batches, messages, queueDepth, exceptions);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        var statsTask = LogStatsAsync(cancellationToken);
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await PendingUpdateSignal.WaitAsync(cancellationToken);
                Interlocked.Increment(ref _signalsThisWindow);

                await UnifiedTracking.UpdateData(cancellationToken);

                lock (SendQueueLock)
                {
                    if (SendQueue.Count <= 0)
                        continue;

                    (_dispatchBuffer, SendQueue) = (SendQueue, _dispatchBuffer);
                }

                await _sendService.Send(_dispatchBuffer, cancellationToken);
                Interlocked.Increment(ref _batchesThisWindow);
                Interlocked.Add(ref _messagesThisWindow, _dispatchBuffer.Count);
                _dispatchBuffer.Clear();
            }
            catch (Exception e)
            {
                Interlocked.Increment(ref _exceptionsThisWindow);
                _logger.LogError(e, "ParameterSender loop exception.");
                SentrySdk.CaptureException(e, scope =>
                {
                    lock (SendQueueLock)
                    {
                        var i = 0;
                        foreach (var msg in SendQueue)
                        {
                            scope.SetExtra($"Address {i}", msg.Address);
                            scope.SetExtra($"Values {i}", msg._meta.ValueLength);
                            scope.SetExtra($"Value 0 {i}", msg.Value);
                            i++;
                        }
                    }
                });
            }
        }

        try
        {
            await statsTask;
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }
}
