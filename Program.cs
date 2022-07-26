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
    private IntPtr handle;
    private NamedPipeClientStream _pipe;
    private IntPtr completionHandle;

    public NamedPipeConnectionFactory(string pipeName) {
        _pipeName = pipeName;
       
        //this._pipe = new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle: this.handle);
    }

    public async ValueTask<Stream> ConnectAsync2(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken)
    {
        var buffer = new byte[24];
        int numWrite = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", buffer);
        var client = new NamedPipeClientStream(".",
            "containerd-containerd",
            PipeDirection.InOut,
            PipeOptions.Asynchronous,
            TokenImpersonationLevel.Anonymous);

        await client.ConnectAsync();
        await client.WriteAsync(buffer.AsMemory(0, numWrite));
        return client;
    }

    public async ValueTask<Stream> ConnectAsync3(SocketsHttpConnectionContext socketsHttpConnectionContext, CancellationToken cancellationToken) 
    {
        // Write preface
        int pipeFlags = SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS | FILE_FLAG_OVERLAPPED;
        //int fileAccess = unchecked((int)(GENERIC_READ | GENERIC_WRITE));
        uint fileAccess = GENERIC_READ | GENERIC_WRITE;
        //int fileAccess = FILE_READ_DATA | FILE_WRITE_ATTRIBUTES;
        var secAttributes = default(SECURITY_ATTRIBUTES);
        this.handle = CreateNamedPipeClient(
            $"\\\\.\\pipe\\containerd-containerd",// _pipeName,
            fileAccess,           // read access that allows to set ReadMode to message on lines 114 & 172
            0,                  // sharing: none
            ref secAttributes,           // security attributes
            FileMode.Open,      // open existing
            SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS | FILE_FLAG_OVERLAPPED,         // impersonation flags
            IntPtr.Zero);  // template file: null
        int error = Marshal.GetLastWin32Error();

        
        var handle2 = CreateNamedPipeClient(
            $"\\\\.\\pipe\\containerd-containerd",// _pipeName,
            fileAccess,           // read access that allows to set ReadMode to message on lines 114 & 172
            0,                  // sharing: none
            ref secAttributes,           // security attributes
            FileMode.Open,      // open existing
            SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS | FILE_FLAG_OVERLAPPED,         // impersonation flags
            IntPtr.Zero);  // template file: null
        error = Marshal.GetLastWin32Error();
        var buffer = new byte[24];
        int numWrite = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", buffer);
        NativeOverlapped nativeOverlapped = new NativeOverlapped();
        ManualResetEvent eventWaitHandle = new ManualResetEvent(false);
        var writtenBytes = (uint)numWrite;

        _pipe = new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle: new SafePipeHandle(handle2, ownsHandle: true));
        var buffer2 = new byte[24];
        //await _pipe.ConnectAsync();
        await _pipe.WriteAsync(buffer.AsMemory(0, numWrite));
        return _pipe;
    }



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
            int pipeFlags = FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS;
            //int fileAccess = unchecked((int)(GENERIC_READ | GENERIC_WRITE));
            uint fileAccess = GENERIC_READ | GENERIC_WRITE;
            //int fileAccess = FILE_READ_DATA | FILE_WRITE_ATTRIBUTES;
            var secAttributes = default(SECURITY_ATTRIBUTES);
            this.handle = CreateNamedPipeClient(
                $"\\\\.\\pipe\\containerd-containerd",// _pipeName,
                fileAccess,           // read access that allows to set ReadMode to message on lines 114 & 172
                0,                  // sharing: none
                ref secAttributes,           // security attributes
                FileMode.Open,      // open existing
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,         // impersonation flags
                IntPtr.Zero);  // template file: null
            int error = Marshal.GetLastWin32Error();
            
            //StartCompletionRoutine();
            //var fileCompletionPort = CreateIoCompletionPort(this.handle, this.completionHandle, UIntPtr.Zero, 4294967295);
            //error = Marshal.GetLastWin32Error();
            //bool notification = SetFileCompletionNotificationModes(this.handle, 1 | 2);

            var buffer = new byte[24];
            int numWrite = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", buffer);
            NativeOverlapped nativeOverlapped = new NativeOverlapped();
            ManualResetEvent eventWaitHandle = new ManualResetEvent(false);
            nativeOverlapped.EventHandle = eventWaitHandle.SafeWaitHandle.DangerousGetHandle();
            //IntPtr intPtr = this.handle.DangerousGetHandle();
            var writtenBytes = (uint)numWrite;

            //_pipe = new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle: this.handle);
            //_pipe = new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle: new SafePipeHandle(handle, ownsHandle:false));
            //await _pipe.WriteAsync(buffer, 0, numWrite);
            //var buffer2 = new byte[64];
            //int numWrite2 = Encoding.ASCII.GetBytes("\x00\x00\x00\x04\x00\x00\x00\x00\x00", buffer2);
            //await _pipe.WriteAsync(buffer2, 0, numWrite2);

            //await Task.WhenAny(preface, settings);

            var write = WriteFile(this.handle, buffer, writtenBytes, out uint bytesWritten, ref nativeOverlapped);
            error = Marshal.GetLastWin32Error();
            uint bytesWritten6;
            if (error == 997)
                GetOverlappedResult(handle, ref nativeOverlapped, out bytesWritten6, true);
            eventWaitHandle.WaitOne();



            await Task.Delay(8000);
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
        _pipe = new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, safePipeHandle: new SafePipeHandle(handle, ownsHandle:true));
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