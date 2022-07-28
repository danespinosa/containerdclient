using Containerd.Services.Containers.V1;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.Win32.SafeHandles;
using System;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using static Pipes;

const string sockPath = "/run/containerd/containerd.sock";
const string pipeName = @"\\.\pipe\containerd-containerd";
bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
Console.WriteLine($"Check pipe: {File.Exists(@"\\.\pipe\containerd-containerd")}");
IConnectionFactory connectionFactory = isWindows ? new NamedPipeConnectionFactory(pipeName) : new UnixDomainSocketConnectionFactory(sockPath);
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
    private SafePipeHandle handle;
    private NamedPipeClientStream _pipe;
    public NamedPipeConnectionFactory(string pipeName)
    {
        uint pipeFlags = FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS;
        uint fileAccess = GENERIC_READ | GENERIC_WRITE;
        int error;
        this.handle = CreateFileW(
            pipeName,// the pipe name,
            fileAccess,           // read access that allows to set ReadMode to message on lines 114 & 172
            0,                  // sharing: none
            IntPtr.Zero,           // security attributes
            FileMode.Open,      // open existing
            pipeFlags,         // impersonation flags
            IntPtr.Zero);  // template file: null
        if (this.handle == null)
        {
            error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"Failed to create file for pipe. Win error: {error}");
        }

        _pipe = new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle: handle);
    }

    public ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken)
    {
        /// Unblock the pipe by reading the first messages from the pipe which tells the HTTP/2 client how to behave.
        /// This approach is not 100% compatible with the current HTTP Client implementation so we skip the HttpClient processing this first message.
        _ = Task.Run(async () =>
        {
            var b = new byte[32];
            var bytes = await _pipe.ReadAsync(b);
            Console.WriteLine($"Read {bytes} from named pipe to avoid blocking further calls.");
        }, cancellationToken);

        var http2Stream = new Http2Stream(_pipe);
        return new ValueTask<Stream>(http2Stream);
    }
}

public interface IConnectionFactory
{
    ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken);
}

class Http2Stream : Stream
{
    static object settingsFrameReadLock = new object();
    public Http2Stream(NamedPipeClientStream namedPipeClientStream)
    {
        namedpipeClientStream = namedPipeClientStream;
        this.isFirst = true;
    }

    public override bool CanRead => namedpipeClientStream.CanRead;

    public override bool CanSeek => namedpipeClientStream.CanSeek;

    public override bool CanWrite => namedpipeClientStream.CanWrite;

    public override long Length => namedpipeClientStream.Position;

    public override long Position { get { return this.namedpipeClientStream.Position; } set  { this.namedpipeClientStream.Position = value; } }
    private NamedPipeClientStream namedpipeClientStream { get; }

    private bool isFirst;

    public override void Flush()
    {
        this.namedpipeClientStream.Flush();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return this.namedpipeClientStream.Read(buffer, offset, count);
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        return this.namedpipeClientStream.Seek(offset, origin);
    }

    public override void SetLength(long value)
    {
        this.namedpipeClientStream.SetLength(value);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        this.namedpipeClientStream.Write(buffer, offset, count);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return this.namedpipeClientStream.ReadAsync(buffer, offset, count, cancellationToken);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        /// We do the first read synchronously, this gets the settings headers.
        /// Modifying the byte 4 is necessary to tell the HTTP Client 2 that we did all the necessary preface/header communication beforehand.
        if (isFirst)
        {
            lock (settingsFrameReadLock)
            {
                if (isFirst)
                {
                    isFirst = false;
                    byte[] settingsBuffer = new byte[9];
                    var settingsReadBytes = this.namedpipeClientStream.Read(settingsBuffer, 0, settingsBuffer.Length);

                    //See Line 1882 & 1845
                    //https://github.com/dotnet/runtime/blob/release/6.0/src/libraries/System.Net.Http/src/System/Net/Http/SocketsHttpHandler/Http2Connection.cs
                    // byte 4 sets the flags
                    // 4 means EndHeaders.
                    settingsBuffer[4] = 4;
                    settingsBuffer.CopyTo(buffer);
                    return settingsReadBytes;
                }
            }
        }

        var readBytes = await this.namedpipeClientStream.ReadAsync(buffer, cancellationToken);
        return readBytes;
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return this.namedpipeClientStream.WriteAsync(buffer, offset, count, cancellationToken);
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return this.namedpipeClientStream.WriteAsync(buffer, cancellationToken);
    }
}