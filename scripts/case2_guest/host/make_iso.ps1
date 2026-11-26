param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Output, [string]$Label = 'CASE2DATA')
$ErrorActionPreference = 'Stop'
if (Test-Path $Output) { throw "$Output already exists" }
Add-Type -CompilerParameters (New-Object CodeDom.Compiler.CompilerParameters -Property @{ CompilerOptions = '/unsafe' }) -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
public static class IsoWriter {
    public static unsafe void Write(object stream, string path, int blockSize, int blocks) {
        IStream s = (IStream)stream;
        byte[] buf = new byte[blockSize * 64];
        int read = 0;
        using (FileStream f = File.Create(path)) {
            long remaining = (long)blockSize * blocks;
            while (remaining > 0) {
                int want = (int)Math.Min(buf.Length, remaining);
                s.Read(buf, want, (IntPtr)(&read));
                if (read <= 0) throw new IOException("Short read from IMAPI stream");
                f.Write(buf, 0, read);
                remaining -= read;
            }
        }
    }
}
'@
$fs = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fs.FileSystemsToCreate = 7   # ISO9660 + Joliet + UDF
$fs.VolumeName = $Label
$fs.FreeMediaBlocks = 0
$fs.Root.AddTree($Source, $false)
$img = $fs.CreateResultImage()
[IsoWriter]::Write($img.ImageStream, $Output, $img.BlockSize, $img.TotalBlocks)
Get-Item $Output | Select-Object Name, Length
