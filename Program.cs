using Containerd.Services.Containers.V1;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.Win32.SafeHandles;
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
        uint access = GenericOperations.GENERIC_READ | GenericOperations.GENERIC_WRITE;
        int intAccess = unchecked((int)access);
        var secAtt = new SECURITY_ATTRIBUTES();
        int _pipeFlags = GenericOperations.FILE_FLAG_OVERLAPPED | GenericOperations.cSECURITY_SQOS_PRESENT | GenericOperations.cSECURITY_ANONYMOUS;
        SafePipeHandle handle = CreateNamedPipeClient("\\\\.\\pipe\\containerd-containerd",
                                      intAccess,           // read and write access
                                      0,                  // sharing: none
                                      ref secAtt,           // security attributes
                                      FileMode.Open,      // open existing
                                      _pipeFlags,         // impersonation flags
                                      IntPtr.Zero);  // template file: null
        //_pipe = new NamedPipeClientStream(
        //    ".",
        //    _pipeName,
        //    direction: PipeDirection.InOut,
        //    options: PipeOptions.Asynchronous,
        //    impersonationLevel: TokenImpersonationLevel.Identification,
        //    inheritability: System.IO.HandleInheritability.None);
        //}

        _pipe = new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle: handle);
    }
    public async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken)
    {
     
        try
        {
            //await _pipe.ConnectAsync(timeout: 1000, cancellationToken);
            //if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            //{
            //    _pipe.ReadMode = PipeTransmissionMode.Byte;
            //}

            Console.WriteLine("connected");
        }
        catch
        {
            await _pipe.DisposeAsync();
            throw;
        }
        return _pipe;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, BestFitMapping = false)]
    internal static extern SafePipeHandle CreateNamedPipeClient(
           string? lpFileName,
           int dwDesiredAccess,
           System.IO.FileShare dwShareMode,
           ref SECURITY_ATTRIBUTES secAttrs,
           FileMode dwCreationDisposition,
           int dwFlagsAndAttributes,
           IntPtr hTemplateFile);
}

public interface IConnectionFactory
{
    ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken);
}

[StructLayout(LayoutKind.Sequential)]
internal struct SECURITY_ATTRIBUTES
{
    internal uint nLength;
    internal IntPtr lpSecurityDescriptor;
    internal BOOL bInheritHandle;
}

/// </remarks>
internal enum BOOL : int
{
    FALSE = 0,
    TRUE = 1,
}

internal static partial class GenericOperations
{
    internal const uint GENERIC_READ = 0x80000000;
    internal const int GENERIC_WRITE = 0x40000000;
    internal const int FILE_FLAG_OVERLAPPED = 0x40000000;
    internal const int cSECURITY_SQOS_PRESENT = 0x100000;

    internal const int cSECURITY_ANONYMOUS = 0;
}