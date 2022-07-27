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
// IConnectionFactory connectionFactory = new UnixDomainSocketConnectionFactory(pipeName);
var socketsHttpHandler = new SocketsHttpHandler
{
    ConnectCallback = connectionFactory.ConnectAsync,
    //PlaintextStreamFilter = PlainTextStreamFilter
};

async ValueTask<Stream> PlainTextStreamFilter(SocketsHttpPlaintextStreamFilterContext arg1, CancellationToken arg2)
{
    var http2Stream = new Http2Stream((NamedPipeClientStream)arg1.PlaintextStream);
    var b = new byte[32000];
    var bytes = await http2Stream.ReadAsync(b);

    return http2Stream;
}

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
    private IntPtr handle;
    private NamedPipeClientStream _pipe;
    private IntPtr completionHandle;

    public NamedPipeConnectionFactory(string pipeName) {
        _pipeName = pipeName;
       
        //this._pipe = new namedpipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle: this.handle);
    }

    //public async ValueTask<Stream> ConnectAsync2(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken)
    //{
    //    var buffer = new byte[24];
    //    int numWrite = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", buffer);
    //    var client = new namedpipeClientStream(".",
    //        "containerd-containerd",
    //        PipeDirection.InOut,
    //        PipeOptions.Asynchronous,
    //        TokenImpersonationLevel.Anonymous);

    //    await client.ConnectAsync();
    //    await client.
    //    (buffer.AsMemory(0, numWrite));
    //    return client;
    //}

    //public async ValueTask<Stream> ConnectAsync3(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken) 
    //{
    //    // Write preface
    //    int pipeFlags = SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS | FILE_FLAG_OVERLAPPED;
    //    //int fileAccess = unchecked((int)(GENERIC_READ | GENERIC_WRITE));
    //    uint fileAccess = GENERIC_READ | GENERIC_WRITE;
    //    //int fileAccess = FILE_READ_DATA | FILE_WRITE_ATTRIBUTES;
    //    var secAttributes = default(SECURITY_ATTRIBUTES);
    //    this.handle = CreateFileW(
    //        $"\\\\.\\pipe\\containerd-containerd",// _pipeName,
    //        fileAccess,           // read access that allows to set ReadMode to message on lines 114 & 172
    //        0,                  // sharing: none
    //        ref secAttributes,           // security attributes
    //        FileMode.Open,      // open existing
    //        SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS | FILE_FLAG_OVERLAPPED,         // impersonation flags
    //        IntPtr.Zero);  // template file: null
    //    int error = Marshal.GetLastWin32Error();

        
    //    var handle2 = CreateFileW(
    //        $"\\\\.\\pipe\\containerd-containerd",// _pipeName,
    //        fileAccess,           // read access that allows to set ReadMode to message on lines 114 & 172
    //        0,                  // sharing: none
    //        ref secAttributes,           // security attributes
    //        FileMode.Open,      // open existing
    //        SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS | FILE_FLAG_OVERLAPPED,         // impersonation flags
    //        IntPtr.Zero);  // template file: null
    //    error = Marshal.GetLastWin32Error();
    //    var buffer = new byte[24];
    //    int numWrite = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", buffer);
    //    NativeOverlapped nativeOverlapped = new NativeOverlapped();
    //    ManualResetEvent eventWaitHandle = new ManualResetEvent(false);
    //    var writtenBytes = (uint)numWrite;

    //    _pipe = new namedpipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle: new SafePipeHandle(handle2, ownsHandle: true));
    //    var buffer2 = new byte[24];
    //    //await _pipe.ConnectAsync();
    //    await _pipe.WriteAsync(buffer.AsMemory(0, numWrite));
    //    return _pipe;
    //}

    public async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken)
    {
     
        try
        {
            // await _pipe.ConnectAsync(timeout: 1000, cancellationToken);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                //_pipe.ReadMode = PipeTransmissionMode.Byte;
            }

            // Write preface
            uint pipeFlags = FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS;
            uint fileAccess = GENERIC_READ | GENERIC_WRITE;
            int error;
            this.handle = CreateFileW(
                _pipeName,// _pipeName,
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
            //var http2Stream = new Http2Stream(_pipe);
            //var b = new byte[32000];
            //var bytes = await http2Stream.ReadAsync(b);

            //return http2Stream;

            var read = Task.Run(async () =>
            {
                var b = new byte[32000];
                int i = 0;
                var bytes = await _pipe.ReadAsync(b);
                Console.WriteLine($"Read {bytes}");
            });

            //var buffer = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

            ////await _pipe.WriteAsync(buffer);
            //var write = WriteFile(this.handle, buffer, buffer.Length, IntPtr.Zero, IntPtr.Zero);
            //error = Marshal.GetLastWin32Error();
            //byte[] settings = new byte[8];
            //write = WriteFile(this.handle, settings, settings.Length, IntPtr.Zero, IntPtr.Zero);
            //error = Marshal.GetLastWin32Error();
            //await Task.Delay(8000);
            //write = WriteFile(handle, buffer, writtenBytes, out uint bytesWritten2, ref nativeOverlapped);
            //error = Marshal.GetLastWin32Error();
            //_pipe.Write(buffer, 0, numWrite);
            // Write Settings
            //numWrite = Encoding.ASCII.GetBytes(String.Empty, buffer);
            //WriteFile(handle, buffer, (uint)numWrite, out uint bytesWritten3, ref nativeOverlapped);

            Console.WriteLine("connected");
        }
        catch
        {
            //await _pipe.DisposeAsync();
            throw;
        }

        return _pipe;
    }

    private void StartCompletionRoutine()
    {
        this.completionHandle = CreateIoCompletionPort(IntPtr.MaxValue, IntPtr.Zero, UIntPtr.Zero, 4294967295);
        _ = Task.Run(() =>
        {
            while (true)
            {
                UIntPtr key;
                IntPtr overlapped;
                bool result = GetQueuedCompletionStatus(completionHandle, out uint lpNumberOfBytes, out key, out overlapped, INFINITE);
                if (result) 
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"Error in queue {error}");
                }
                Console.WriteLine("Got status");
            }
        }).ConfigureAwait(false);
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
        this.frameReadBytes = 0;
    }

    public override bool CanRead => namedpipeClientStream.CanRead;

    public override bool CanSeek => namedpipeClientStream.CanSeek;

    public override bool CanWrite => namedpipeClientStream.CanWrite;

    public override long Length => namedpipeClientStream.Position;

    public override long Position { get { return this.namedpipeClientStream.Position; } set  { this.namedpipeClientStream.Position = value; } }
    private NamedPipeClientStream namedpipeClientStream { get; }

    private bool isFirst;
    private int frameReadBytes;
    private byte[]? settingsBuffer;

    public override void Flush()
    {
        this.namedpipeClientStream.Flush();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {

        if (isFirst)
        {
            lock (settingsFrameReadLock)
            {
                if (isFirst)
                {
                    // The first read unblocks the blocked call, but when reading then we get the first Frames that are the FrameSettings returned from the Server.
                    // We store those settings back so the HTTP/2.0 client receives the right settings the first time the http2/client tries to read those settings.
                    this.frameReadBytes = this.namedpipeClientStream.Read(buffer, offset, count);
                    this.settingsBuffer = new byte[buffer.Length];
                    CopyBytesFromBufferToBuffer(buffer, settingsBuffer, this.frameReadBytes);
                    isFirst = false;

                    return 0;
                }
            }
        }

        //if (this.settingsBuffer != null)
        //{
        //    lock (settingsFrameReadLock)
        //    {
        //        if (this.settingsBuffer != null)
        //        {
        //            CopyBytesFromBufferToBuffer(settingsBuffer, buffer, this.frameReadBytes);
                    
        //            this.settingsBuffer = null;
        //            return frameReadBytes;
        //        }
        //    }
        //}

        var readBytes = this.namedpipeClientStream.Read(buffer, offset, count);
        return readBytes;
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

    private void CopyBytesFromBufferToBuffer(byte[] bufferA, byte[] bufferB, int count) 
    {
        if (bufferB.Length < count)
        {
            throw new InvalidOperationException($"The buffer b size has to be at least of size {count}");
        }
        for (int i = 0; i < count; i++)
        {
            bufferB[i] = bufferA[i];
        }
    }
}