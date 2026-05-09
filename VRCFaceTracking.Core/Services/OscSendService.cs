using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Microsoft.Extensions.Logging;
using VRCFaceTracking.Core.Contracts;
using VRCFaceTracking.Core.OSC;

namespace VRCFaceTracking.Core.Services;

/**
 * OscSendService is responsible for encoding osc messages and sending them over OSC
 */
public class OscSendService
{
    private readonly ILogger<OscSendService> _logger;
    private readonly IOscTarget _oscTarget;
    private readonly object _socketLock = new();
    private readonly Timer _statsTimer;

    private Socket _sendSocket;
    private IPEndPoint? _currentEndpoint;
    private readonly byte[] _sendBuffer = new byte[4096];
    private OscMessageMeta[] _metaBuffer = new OscMessageMeta[256];
    private int _successfulDispatchesThisWindow;
    private int _batchesThisWindow;
    private int _failedDispatchesThisWindow;

    private CancellationTokenSource _cts;
    public Action<int> OnMessagesDispatched = _ => { };

    public OscSendService(
        ILogger<OscSendService> logger,
        IOscTarget oscTarget
    )
    {
        _logger = logger;
        _cts = new CancellationTokenSource();
        _statsTimer = new Timer(_ => LogStats(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));

        _oscTarget = oscTarget;

        _oscTarget.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName is not nameof(IOscTarget.OutPort) &&
                args.PropertyName is not nameof(IOscTarget.DestinationAddress))
            {
                return;
            }

            if (_oscTarget.OutPort == default)
            {
                return;
            }

            if (string.IsNullOrEmpty(_oscTarget.DestinationAddress))
            {
                _oscTarget.DestinationAddress = "127.0.0.1";
            }

            UpdateTarget(new IPEndPoint(IPAddress.Parse(_oscTarget.DestinationAddress), _oscTarget.OutPort));
        };
    }

    private void LogStats()
    {
        var dispatched = Interlocked.Exchange(ref _successfulDispatchesThisWindow, 0);
        var batches = Interlocked.Exchange(ref _batchesThisWindow, 0);
        var failures = Interlocked.Exchange(ref _failedDispatchesThisWindow, 0);
        var endpoint = _currentEndpoint?.ToString() ?? "unset";

        _logger.LogInformation(
            "OscSend stats: dispatched={dispatched} batches={batches} failures={failures} connected={connected} endpoint={endpoint}",
            dispatched,
            batches,
            failures,
            _oscTarget.IsConnected,
            endpoint);
    }

    private void UpdateTarget(IPEndPoint endpoint)
    {
        lock (_socketLock)
        {
            _cts.Cancel();
            _sendSocket?.Close();
            _oscTarget.IsConnected = false;
            _currentEndpoint = endpoint;

            _sendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            try
            {
                _sendSocket.Connect(endpoint);
                _oscTarget.IsConnected = true;
            }
            catch (SocketException ex)
            {
                _logger.LogWarning($"Failed to bind to sender endpoint: {endpoint}. {ex.Message}");
            }
            finally
            {
                _cts = new CancellationTokenSource();
            }
        }
    }

    private async Task<bool> TrySendAsync(ReadOnlyMemory<byte> payload)
    {
        Socket socket;
        lock (_socketLock)
        {
            socket = _sendSocket;
        }

        try
        {
            if (socket is null || !socket.Connected)
            {
                if (_currentEndpoint is null)
                {
                    Interlocked.Increment(ref _failedDispatchesThisWindow);
                    return false;
                }

                UpdateTarget(_currentEndpoint);
                lock (_socketLock)
                {
                    socket = _sendSocket;
                }
            }

            await socket.SendAsync(payload);
            return true;
        }
        catch (ObjectDisposedException)
        {
            if (_currentEndpoint is null)
            {
                Interlocked.Increment(ref _failedDispatchesThisWindow);
                return false;
            }

            _logger.LogWarning("OSC send socket was disposed. Rebinding sender endpoint.");
            UpdateTarget(_currentEndpoint);
            lock (_socketLock)
            {
                socket = _sendSocket;
            }

            try
            {
                await socket.SendAsync(payload);
                return true;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _failedDispatchesThisWindow);
                _logger.LogWarning(ex, "OSC send retry failed after socket disposal.");
                _oscTarget.IsConnected = false;
                return false;
            }
        }
        catch (SocketException ex)
        {
            if (_currentEndpoint is null)
            {
                Interlocked.Increment(ref _failedDispatchesThisWindow);
                _logger.LogWarning(ex, "OSC send failed and no endpoint is configured.");
                _oscTarget.IsConnected = false;
                return false;
            }

            _logger.LogWarning(ex, "OSC send failed. Rebinding sender endpoint and retrying.");
            UpdateTarget(_currentEndpoint);
            lock (_socketLock)
            {
                socket = _sendSocket;
            }

            try
            {
                await socket.SendAsync(payload);
                return true;
            }
            catch (Exception retryEx)
            {
                Interlocked.Increment(ref _failedDispatchesThisWindow);
                _logger.LogWarning(retryEx, "OSC send retry failed after rebinding sender endpoint.");
                _oscTarget.IsConnected = false;
                return false;
            }
        }
    }

    public async Task Send(OscMessage message, CancellationToken ct)
    {
        var nextByteIndex = await message.Encode(_sendBuffer, ct);
        if (nextByteIndex > _sendBuffer.Length)
        {
            Interlocked.Increment(ref _failedDispatchesThisWindow);
            _logger.LogError("OSC message too large to send! Skipping this batch of messages.");
            return;
        }

        if (await TrySendAsync(_sendBuffer.AsMemory(0, nextByteIndex)))
        {
            Interlocked.Increment(ref _batchesThisWindow);
            Interlocked.Increment(ref _successfulDispatchesThisWindow);
            OnMessagesDispatched(1);
        }
    }

    public Task Send(OscMessage[] messages, CancellationToken ct) => Send((IReadOnlyList<OscMessage>)messages, ct);

    public async Task Send(IReadOnlyList<OscMessage> messages, CancellationToken ct)
    {
        EnsureMetaBuffer(messages.Count);
        for (var i = 0; i < messages.Count; i++)
            _metaBuffer[i] = messages[i]._meta;

        var index = 0;
        while (index < messages.Count)
        {
            ct.ThrowIfCancellationRequested();
            var length = fti_osc.create_osc_bundle(_sendBuffer, _metaBuffer, messages.Count, ref index);
            if (!await TrySendAsync(_sendBuffer.AsMemory(0, length)))
                return;
        }

        Interlocked.Increment(ref _batchesThisWindow);
        Interlocked.Add(ref _successfulDispatchesThisWindow, index);
        OnMessagesDispatched(index);
    }

    private void EnsureMetaBuffer(int requiredLength)
    {
        if (_metaBuffer.Length >= requiredLength)
            return;

        Array.Resize(ref _metaBuffer, requiredLength);
    }
}
