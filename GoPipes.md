
```go
GrpcClient1// access
return DialPipeAccess(ctx, path, syscall.GENERIC_READ|syscall.GENERIC_WRITE)
// attributes
h, err := createFile(*path, access, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OVERLAPPED|cSECURITY_SQOS_PRESENT|cSECURITY_ANONYMOUS, 0)

// sys call
func _createFile(name *uint16, access uint32, mode uint32, sa *syscall.SecurityAttributes, createmode uint32, attrs uint32, templatefile syscall.Handle) (handle syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall9(procCreateFileW.Addr(), 7, uintptr(unsafe.Pointer(name)), uintptr(access), uintptr(mode), uintptr(unsafe.Pointer(sa)), uintptr(createmode), uintptr(attrs), uintptr(templatefile), 0, 0)
	handle = syscall.Handle(r0)
	if handle == syscall.InvalidHandle {
		err = errnoErr(e1)
	}
	return
}

// name ////.//pipe//containerd-containerd
// access Read | Write In | Out
// Mode: 0
// sa: nil/default no inheritability
// create mode OPEN / 3 default
// attrs: syscall.FILE_FLAG_OVERLAPPED|cSECURITY_SQOS_PRESENT|cSECURITY_ANONYMOUS // None token and Anonymous and Asynchronous
// template file 0
```

refrences: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew  
http://pinvoke.net/default.aspx/kernel32/CreateFile.html  
https://docs.microsoft.com/en-us/aspnet/core/grpc/client?view=aspnetcore-6.0#configure-grpc-client
