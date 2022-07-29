using Containerd.Services.Containers.V1;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.Win32.SafeHandles;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using static Pipes;

const string pipeName = @"\\.\pipe\containerd-containerd";
Console.WriteLine($"Check pipe: {File.Exists(@"\\.\pipe\containerd-containerd")}");
IConnectionFactory connectionFactory = new NamedPipeConnectionFactory(pipeName);
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
    private IntPtr handle;
    private NamedPipeClientStream _pipe;

    public NamedPipeConnectionFactory(string pipeName)
    {
        uint pipeFlags = FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS;
        uint fileAccess = GENERIC_READ | GENERIC_WRITE;
        int error;
        this.handle = CreateFileW(
            $"\\\\.\\pipe\\containerd-containerd",// _pipeName,
            fileAccess,           // read access that allows to set ReadMode to message on lines 114 & 172
            0,                  // sharing: none
            IntPtr.Zero,           // security attributes
            FileMode.Open,      // open existing
            pipeFlags,         // impersonation flags
            IntPtr.Zero);  // template file: null
        if (this.handle == (IntPtr)(-1))
        {
            error = Marshal.GetLastWin32Error();
        }
        _pipe = new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle: new SafePipeHandle(handle, ownsHandle: true));
    }

    public ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken)
    {
        return new ValueTask<Stream>(_pipe);
    }
}

public interface IConnectionFactory
{
    ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken);
}