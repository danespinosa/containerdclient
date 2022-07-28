using System.Net;
using System.Net.Sockets;

public class UnixDomainSocketConnectionFactory : IConnectionFactory
{
    private readonly EndPoint _endPoint;
    private readonly Socket _socket;

    public UnixDomainSocketConnectionFactory(string sockPath)
    {
        _endPoint = new UnixDomainSocketEndPoint(sockPath);
        _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
    }

    public async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext _,
        CancellationToken cancellationToken = default)
    {
        await _socket.ConnectAsync(_endPoint, cancellationToken).ConfigureAwait(false);
        return new NetworkStream(_socket, true);
    }

    public void Dispose()
    {
        _socket.Dispose();
    }
}