// Trusted support for bounded input, protected-path IO, and owned child processes.
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.ComponentModel;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class ValidationInput {
    public static string Read() {
        Stream stream = Console.OpenStandardInput();
        byte[] buffer = new byte[8193];
        int count = 0;
        Stopwatch timer = Stopwatch.StartNew();
        while (count < buffer.Length) {
            var pending = stream.ReadAsync(buffer, count, buffer.Length - count);
            int remaining = 10000 - (int)timer.ElapsedMilliseconds;
            if (remaining <= 0 || !pending.Wait(remaining)) throw new IOException("input_timeout");
            int read = pending.Result;
            if (read == 0) return new UTF8Encoding(false, true).GetString(buffer, 0, count);
            count += read;
        }
        throw new IOException("request_too_large");
    }
}

// Hold directory handles without FILE_SHARE_DELETE for the entire transaction.
// Never follow a reparse point, accept a hard-linked file, or trust a pre-open check.
public sealed class ValidationStore : IDisposable {
    readonly List<SafeFileHandle> directories = new List<SafeFileHandle>();
    FileStream gate;
    readonly string root;
    [StructLayout(LayoutKind.Sequential)] struct Info {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
    static void Verify(SafeFileHandle handle, string expected, bool directory) {
        Info info;
        if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception();
        if ((info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory || (!directory && info.Links != 1))
            throw new IOException("unsafe_file");
        StringBuilder actual = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandle(handle, actual, (uint)actual.Capacity, 0);
        if (length == 0 || length >= actual.Capacity || !String.Equals(actual.ToString(), "\\\\?\\" + Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase))
            throw new IOException("unexpected_file_identity");
    }
    public ValidationStore(string directory) {
        root = Path.GetFullPath(directory).TrimEnd('\\');
        try {
            string current = Path.GetPathRoot(root);
            Hold(current);
            foreach (string part in root.Substring(current.Length).Split('\\')) {
                current = Path.Combine(current, part); Hold(current);
            }
            string lockPath = Path.Combine(root, "store.lock");
            Stopwatch timer = Stopwatch.StartNew();
            while (true) {
                try { gate = OpenFile(lockPath, true, true); break; }
                catch (IOException) { if (timer.ElapsedMilliseconds >= 5000) throw; System.Threading.Thread.Sleep(25); }
            }
            Verify(gate.SafeFileHandle, lockPath, false);
        } catch { Dispose(); throw; }
    }
    void Hold(string path) {
        SafeFileHandle handle = CreateFile(path, 0x80, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(); }
        directories.Add(handle); Verify(handle, path, true);
    }
    string Resolve(string name) {
        if (!System.Text.RegularExpressions.Regex.IsMatch(name, "\\A[a-z0-9-]+\\.(json|bin)\\z")) throw new IOException("invalid_store_name");
        return Path.Combine(root, name);
    }
    static FileStream OpenFile(string path, bool write, bool create) {
        SafeFileHandle handle = CreateFile(path, write ? 0xc0000000u : 0x80000000u,
            write ? 0u : 1u, IntPtr.Zero, create ? 4u : 3u, 0x00200000, IntPtr.Zero);
        if (handle.IsInvalid) { int code = Marshal.GetLastWin32Error(); handle.Dispose(); throw new IOException("file_open_failed", new Win32Exception(code)); }
        try { Verify(handle, path, false); return new FileStream(handle, write ? FileAccess.ReadWrite : FileAccess.Read); }
        catch { handle.Dispose(); throw; }
    }
    public bool Exists(string name) { return File.Exists(Resolve(name)); }
    public byte[] ReadBytes(string name, int maximum) {
        string path = Resolve(name);
        using (FileStream stream = OpenFile(path, false, false)) {
            if (maximum < 0 || maximum > 16777216 || stream.Length > maximum) throw new IOException("file_too_large");
            byte[] bytes = new byte[(int)stream.Length]; int offset = 0;
            while (offset < bytes.Length) {
                int count = stream.Read(bytes, offset, bytes.Length - offset);
                if (count == 0) throw new IOException("incomplete_file");
                offset += count;
            }
            return bytes;
        }
    }
    public string Read(string name) { return new UTF8Encoding(false, true).GetString(ReadBytes(name, 16777216)); }
    public void Write(string name, string text) {
        string destination = Resolve(name);
        // Verify the old file under the exclusive store lock before atomic replacement.
        if (File.Exists(destination)) Read(name);
        string temporary = Path.Combine(root, Guid.NewGuid().ToString("N") + ".tmp");
        byte[] bytes = new UTF8Encoding(false, true).GetBytes(text);
        using (FileStream stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
            Verify(stream.SafeFileHandle, temporary, false); stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
        }
        if (File.Exists(destination)) File.Replace(temporary, destination, null);
        else File.Move(temporary, destination);
    }
    public string[] Jobs() { return Directory.GetFiles(root, "job-*.json"); }
    public void Dispose() {
        if (gate != null) { gate.Dispose(); gate = null; }
        foreach (SafeFileHandle handle in directories) handle.Dispose();
        directories.Clear();
    }
}

// A Job Object owns only this invocation and descendants. Closing it kills them.
// Start suspended so there is no interval in which the child escapes ownership.
public sealed class ValidationChild : IDisposable {
    IntPtr job, process;
    public uint Id { get; private set; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
        public uint Size; public string Reserved, Desktop, Title; public uint X,Y,W,H,XC,YC,Fill,Flags;
        public ushort Show, ReservedSize; public IntPtr ReservedPtr, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process, Thread; public uint Id, ThreadId; }
    [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
        public long ProcessTime, JobTime; public uint Flags; public UIntPtr MinWorking, MaxWorking;
        public uint ActiveProcesses; public UIntPtr Affinity; public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct Counters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct Limits {
        public BasicLimits Basic; public Counters IO; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int kind, ref Limits limits, uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcess(string app, StringBuilder command, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr environment, string directory, ref Startup startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public ValidationChild(string executable, string arguments, string directory) {
        ProcessInfo child = new ProcessInfo();
        try {
            job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) throw new Win32Exception();
            Limits limits = new Limits(); limits.Basic.Flags = 0x2008; limits.Basic.ActiveProcesses = 8;
            if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(Limits)))) throw new Win32Exception();
            Startup startup = new Startup(); startup.Size = (uint)Marshal.SizeOf(typeof(Startup));
            if (!CreateProcess(executable, new StringBuilder("\"" + executable + "\" " + arguments), IntPtr.Zero, IntPtr.Zero, false, 0x08000004, IntPtr.Zero, directory, ref startup, out child)) throw new Win32Exception();
            process = child.Process; Id = child.Id;
            if (!AssignProcessToJobObject(job, process)) throw new Win32Exception();
            if (ResumeThread(child.Thread) == UInt32.MaxValue) throw new Win32Exception();
        } catch {
            if (child.Process != IntPtr.Zero) TerminateProcess(child.Process, 1);
            Dispose(); throw;
        } finally { if (child.Thread != IntPtr.Zero) CloseHandle(child.Thread); }
    }
    public bool Finished { get { return WaitForSingleObject(process, 0) == 0; } }
    public uint ExitCode { get { uint code; if (!Finished || !GetExitCodeProcess(process, out code)) throw new InvalidOperationException("child_not_finished"); return code; } }
    public void Dispose() {
        if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; }
        if (process != IntPtr.Zero) { WaitForSingleObject(process, 5000); CloseHandle(process); process = IntPtr.Zero; }
    }
}
