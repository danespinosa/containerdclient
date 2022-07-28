// <copyright file="Pipes.cs" company="Microsoft">
// Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>


using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

#nullable enable

/// <summary>
/// Interop structrues to create a Named Pipe.
/// </summary>
internal class Pipes
{
    /// <summary>
    /// File Overlapped flag.
    /// </summary>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea"/>
    internal const int FILE_FLAG_OVERLAPPED = 0x40000000;

    /// <summary>
    /// SQOS Security attribute.
    /// </summary>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea"/>
    internal const int SECURITY_SQOS_PRESENT = 0x100000;

    /// <summary>
    /// Anonymous security flag.
    /// </summary>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea"/>
    internal const int SECURITY_ANONYMOUS = 0;

    /// <summary>
    /// The pipe can read data.
    /// </summary>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights" />
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants" />
    internal const int FILE_READ_DATA = 1;

    /// <summary>
    /// The pipe can write attributes.
    /// </summary>
    // <see href="https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights" />
    // <see href="https://docs.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants" />
    internal const int FILE_WRITE_ATTRIBUTES = 256;

    /// <summary>
    /// Represents the generic read flag for Files and pipes.
    /// </summary>
    internal const uint GENERIC_READ = 0x80000000;

    /// <summary>
    /// Represents the generic read flag for Files and pipes.
    /// </summary>
    internal const int GENERIC_WRITE = 0x40000000;

    /// <summary>
    /// Creates a Named Pipe file.
    /// </summary>
    /// <param name="lpFileName">The file name.</param>
    /// <param name="dwDesiredAccess">The desired access.</param>
    /// <param name="dwShareMode">The shared mode.</param>
    /// <param name="secAttrs">The security attributes.</param>
    /// <param name="dwCreationDisposition">The creation disposition.</param>
    /// <param name="dwFlagsAndAttributes">The flags and attributes.</param>
    /// <param name="hTemplateFile">The template file.</param>
    /// <returns>The Safe Pipe handle.</returns>
    /// <see href="https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea"/>
    /// <see href="https://github.com/dotnet/runtime/blob/a24364a09d9aea98b545f16689a53bafc6b18c14/src/libraries/Common/src/Interop/Windows/Kernel32/Interop.CreateFileW.cs"/>
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, BestFitMapping = false)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern SafePipeHandle CreateFileW(
          string? lpFileName,
          uint dwDesiredAccess,
          FileShare dwShareMode,
          IntPtr secAttrs,
          FileMode dwCreationDisposition,
          uint dwFlagsAndAttributes,
          IntPtr hTemplateFile);
}
#nullable disable