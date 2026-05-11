using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VRCFaceTracking.Core.Models;
using VRCFaceTracking.Core.Sandboxing.IPC;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace VRCFaceTracking.Core.Sandboxing;

public delegate void OnPacketReceivedCallback(in IpcPacket packet);

public class VrcftSandboxClient : UdpFullDuplex
{
    private static readonly TimeSpan HandshakeRetryTimeout = TimeSpan.FromMilliseconds(250);
    // private int                                     _port = 0;
    private IPEndPoint                              _serverEndpoint;
    private readonly ILoggerFactory                 _loggerFactory;
    private readonly ILogger<VrcftSandboxClient>    _logger;
    private bool                                    _isConnected;
    private int                                     _maxPacketSizeBytes;
    private string?                                 _modulePath;
    private int                                     _reconnectInProgress;
    private int                                     _handshakePending;
    private long                                    _lastHandshakeSendTimestamp;
    public bool IsConnected => _isConnected;

    public OnPacketReceivedCallback OnPacketReceivedCallback = null;
    public VrcftSandboxClient(int portNumber,
        ILoggerFactory factory
        ) : base(0, null, new IPEndPoint(IPAddress.Loopback, portNumber)) // 0 is reserved for the OS to pick for us
    {
        _isConnected = false;
        // Init loggers
        _loggerFactory = factory;
        _logger = factory.CreateLogger<VrcftSandboxClient>();

        var addresses = Dns.GetHostAddresses("127.0.0.1");
        if ( addresses.Length == 0 )
        {
            throw new Exception($"Unable to find localhost (how did this even happen??)");
        }

        _serverEndpoint = new IPEndPoint(addresses[0], portNumber);
        Port = ( ( IPEndPoint )_receivingUdpClient.Client.LocalEndPoint ).Port;


        _logger.LogInformation($"Starting sandbox process on port {Port}...");
    }

    public void Connect(in string modulePath)
    {
        _modulePath = modulePath;
        if (!TryBeginHandshake("connect"))
            return;

        var handshakePkt = new HandshakePacket();
        handshakePkt.ModulePath = modulePath;
        _logger.LogInformation($"Attempting to connect to server...");
        if (!TrySendBytes(handshakePkt.GetBytes()))
        {
            Interlocked.Exchange(ref _handshakePending, 0);
            return;
        }
        Interlocked.Exchange(ref _lastHandshakeSendTimestamp, Stopwatch.GetTimestamp());

        // Take the lower bound of packet rate we can fit through the network
        _maxPacketSizeBytes = Math.Min(_receivingUdpClient.Client.ReceiveBufferSize, _receivingUdpClient.Client.SendBufferSize);
    }

    public override void OnBytesReceived(in byte[] data, in IPEndPoint endpoint)
    {
        bool decodeResult = VrcftPacketDecoder.TryDecodePacket(data, out IpcPacket packet);

        if ( decodeResult )
        {
            // Tell the callback that we've received a packet
            if ( OnPacketReceivedCallback != null && packet.GetPacketType() != IpcPacket.PacketType.Unknown )
            {
                if ( packet.GetPacketType() == IpcPacket.PacketType.SplitPacketChunk )
                {
                    PartialPacket.DecodePacket(data, out var combinedData);
                    if ( combinedData.Length > 0 )
                    {
                        OnBytesReceived(combinedData, endpoint);
                    }
                }
                else
                {
                    OnPacketReceivedCallback(packet);
                }
            }

            if ( packet.GetPacketType() == IpcPacket.PacketType.Handshake )
            {
                // Handshake request
                var handshakePacket = (HandshakePacket) packet;
                if ( handshakePacket.IsValid )
                {
                    _logger.LogInformation($"Received ACK from host on port {endpoint.Port}. Handshake done.");
                    _isConnected = true;
                    Interlocked.Exchange(ref _handshakePending, 0);
                    SendAllPendingPackets();
                }
            }
        }
    }

    private bool TryBeginHandshake(string reason)
    {
        if (Interlocked.CompareExchange(ref _handshakePending, 1, 0) == 0)
            return true;

        var staleFor = Stopwatch.GetElapsedTime(Interlocked.Read(ref _lastHandshakeSendTimestamp));
        if (staleFor < HandshakeRetryTimeout)
            return false;

        Interlocked.Exchange(ref _handshakePending, 0);
        return Interlocked.CompareExchange(ref _handshakePending, 1, 0) == 0;
    }

    private bool TrySendBytes(in byte[] message)
    {
        try
        {
            // @TODO: Check packet size, if too big, convert to partial packet, and send partial packets
            _receivingUdpClient.Send(message, message.Length, _serverEndpoint);
            if (!_isConnected && message.Length > 0)
                Interlocked.Exchange(ref _lastHandshakeSendTimestamp, Stopwatch.GetTimestamp());
            return true;
        }
        catch (ObjectDisposedException)
        {
            _isConnected = false;
            return false;
        }
        catch (SocketException)
        {
            _isConnected = false;
            return false;
        }
    }

    private void TryReconnect()
    {
        if (string.IsNullOrWhiteSpace(_modulePath))
            return;

        if (_isConnected)
            return;

        if (!TryBeginHandshake("reconnect"))
            return;

        if (Interlocked.Exchange(ref _reconnectInProgress, 1) == 1)
        {
            Interlocked.Exchange(ref _handshakePending, 0);
            return;
        }

        try
        {
            var handshakePkt = new HandshakePacket
            {
                ModulePath = _modulePath
            };

            if (!TrySendBytes(handshakePkt.GetBytes()))
            {
                Interlocked.Exchange(ref _handshakePending, 0);
            }
            else
            {
                Interlocked.Exchange(ref _lastHandshakeSendTimestamp, Stopwatch.GetTimestamp());
            }
        }
        finally
        {
            Interlocked.Exchange(ref _reconnectInProgress, 0);
        }
    }

    public void SendData(in IpcPacket packet)
    {
        if ( _isConnected || packet.GetPacketType() == IpcPacket.PacketType.Handshake)
        {
            byte[] packetData = packet.GetBytes();
            if ( packetData.Length > MTU )
            {
                // @TODO: Split packet into chunks
                byte[][] packetChunkBytes = PartialPacket.SplitPacketIntoChunks(packetData, MTU);
                foreach ( var packetChunk in packetChunkBytes )
                {
                    if (!TrySendBytes(packetChunk))
                    {
                        _eventBus.Push(packet);
                        TryReconnect();
                        return;
                    }
                    Thread.Sleep(1);    //TODO: Potentially switch to ACK based chunking system
                }
            }
            else
            {
                if (!TrySendBytes(packetData))
                {
                    _eventBus.Push(packet);
                    TryReconnect();
                }
            }
        }
        else
        {
            _eventBus.Push(packet);
            TryReconnect();
        }
    }

    public void SendAllPendingPackets()
    {
        if ( _isConnected )
        {
            if ( _eventBus.Count > 0 )
            {
                while ( _eventBus.Count > 0 )
                {
                    IpcPacket pkt = _eventBus.Pop<IpcPacket>();
                    SendData(pkt);
                }
            }
        }
    }
}
