using Containerd.Services.Containers.V1;
using Grpc.Core;
using Grpc.Net.Client;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;

const string sockPath = "/run/containerd/containerd.sock";
const string pipeName = "containerd-containerd";
bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
Console.WriteLine($"Check pipe: {File.Exists(@"\\.\pipe\containerd-containerd")}");
IConnectionFactory connectionFactory = isWindows ? new NamedPipeConnectionFactory(pipeName) : new UnixDomainSocketConnectionFactory(sockPath);
// IConnectionFactory connectionFactory = new UnixDomainSocketConnectionFactory(pipeName);
var socketsHttpHandler = new SocketsHttpHandler
{
    ConnectCallback = connectionFactory.ConnectAsync,
};
var channel = GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions
{
    HttpHandler = socketsHttpHandler, 
    
});
var client = new Containers.ContainersClient(channel);
var headers = new Metadata
{
    { "containerd-namespace", "default" }
};
var response = await client.ListAsync(new ListContainersRequest(), headers);
if (response == null)
{
    Console.WriteLine("No response");
}
else
{
    Console.WriteLine(response);
}

public sealed class NamedPipeConnectionFactory : IConnectionFactory
{
    private readonly string _pipeName;
    private readonly NamedPipeClientStream _pipe;

    public NamedPipeConnectionFactory(string pipeName) {
        _pipeName = pipeName;
        _pipe = new NamedPipeClientStream(".", _pipeName,
                direction: PipeDirection.InOut,
               options: PipeOptions.Asynchronous,
               impersonationLevel: TokenImpersonationLevel.Anonymous,
               inheritability: System.IO.HandleInheritability.None);
    }
    public async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken)
    {
     
        try
        {
            await _pipe.ConnectAsync(timeout: 1000, cancellationToken);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _pipe.ReadMode = PipeTransmissionMode.Byte;
            }

            Console.WriteLine("connected");
        }
        catch
        {
            await _pipe.DisposeAsync();
            throw;
        }
        return _pipe;
    }
}

public interface IConnectionFactory
{
    ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken);
}