// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

// Read-only observations of two audited engine counters. The selected private
// image's offsets live in a separately approved package member, never a request.
// Zero counters do not by themselves prove variant selection or module closure.
internal sealed class SelectorObservation
{
    internal sealed class Profile
    {
        internal readonly string ImageHash;
        internal readonly ulong PluginsRva, PluginsCountOffset, KeywordsRva, KeywordsCountOffset;

        internal Profile(byte[] bytes)
        {
            if (bytes == null || bytes.Length != 72 ||
                Encoding.ASCII.GetString(bytes, 0, 8) != "DVSEL001")
                throw new InvalidDataException("Invalid selector observation profile");
            var imageHash = new byte[32];
            Array.Copy(bytes, 8, imageHash, 0, imageHash.Length);
            ImageHash = BitConverter.ToString(imageHash).Replace("-", "").ToLowerInvariant();
            if (ImageHash == new string('0', 64))
                throw new InvalidDataException("Missing selector image authority");
            using (var stream = new MemoryStream(bytes, 40, 32, false))
            using (var reader = new BinaryReader(stream))
            {
                PluginsRva = reader.ReadUInt64();
                PluginsCountOffset = reader.ReadUInt64();
                KeywordsRva = reader.ReadUInt64();
                KeywordsCountOffset = reader.ReadUInt64();
            }
            if (!ValidRva(PluginsRva) || !ValidRva(KeywordsRva) || PluginsRva == KeywordsRva ||
                !ValidOffset(PluginsCountOffset) || !ValidOffset(KeywordsCountOffset))
                throw new InvalidDataException("Unsupported selector counter layout");
        }

        static bool ValidRva(ulong value) { return value >= 4096 && value <= uint.MaxValue - 8 && value % 8 == 0; }
        static bool ValidOffset(ulong value) { return value >= 8 && value <= 256 && value % 8 == 0; }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ModuleInfo
    {
        internal IntPtr Base;
        internal uint Size;
        internal IntPtr Entry;
    }

    [DllImport("kernel32", CharSet = CharSet.Unicode)]
    static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32", CharSet = CharSet.Unicode)]
    static extern uint GetModuleFileName(IntPtr module, StringBuilder path, uint size);
    [DllImport("psapi")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetModuleInformation(IntPtr process, IntPtr module, out ModuleInfo info, uint size);
    [DllImport("kernel32")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ReadProcessMemory(IntPtr process, IntPtr address, [Out] byte[] bytes,
                                          UIntPtr count, out UIntPtr read);

    readonly Profile profile;
    readonly ulong moduleBase;
    readonly uint moduleSize;
    internal readonly string ProfileHash;
    internal string ImageHash { get { return profile.ImageHash; } }

    internal SelectorObservation(string packageRoot)
    {
        if (IntPtr.Size != 8 || !BitConverter.IsLittleEndian)
            throw new InvalidOperationException("Selector observation requires little-endian x64");
        byte[] bytes;
        using (var stream = File.OpenRead(Path.Combine(packageRoot, "selector-profile.bin")))
        {
            if (stream.Length != 72) throw new InvalidDataException("Invalid selector profile length");
            using (var reader = new BinaryReader(stream)) bytes = reader.ReadBytes(72);
        }
        profile = new Profile(bytes);
        using (var sha = SHA256.Create())
            ProfileHash = Hex(sha.ComputeHash(bytes));
        IntPtr module = GetModuleHandle("UnityPlayer.dll");
        ModuleInfo info;
        if (module == IntPtr.Zero || !GetModuleInformation(new IntPtr(-1), module, out info,
                                                          (uint)Marshal.SizeOf(typeof(ModuleInfo))) ||
            info.Base != module || info.Size < 8)
            throw new InvalidOperationException("Loaded selector image unavailable");
        moduleBase = checked((ulong)module.ToInt64());
        moduleSize = info.Size;
        if (profile.PluginsRva > moduleSize - 8 || profile.KeywordsRva > moduleSize - 8)
            throw new InvalidDataException("Selector pointer outside loaded image");
        var path = new StringBuilder(4096);
        uint length = GetModuleFileName(module, path, (uint)path.Capacity);
        if (length == 0 || length >= path.Capacity)
            throw new InvalidOperationException("Loaded selector path unavailable");
        using (var stream = File.OpenRead(path.ToString()))
        using (var sha = SHA256.Create())
            if (Hex(sha.ComputeHash(stream)) != profile.ImageHash)
                throw new InvalidDataException("Loaded selector image differs from audited profile");
    }

    static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }

    static ulong ReadWord(ulong address)
    {
        if (address < 65536 || address > (ulong)long.MaxValue - 8 || address % 8 != 0)
            throw new InvalidDataException("Invalid selector address");
        var bytes = new byte[8];
        UIntPtr read;
        if (!ReadProcessMemory(new IntPtr(-1), new IntPtr((long)address), bytes, new UIntPtr(8), out read) ||
            read.ToUInt64() != 8)
            throw new InvalidOperationException("Selector state is unreadable");
        return BitConverter.ToUInt64(bytes, 0);
    }

    ulong Counter(ulong rva, ulong offset)
    {
        ulong pointer = ReadWord(checked(moduleBase + rva));
        if (pointer == 0) throw new InvalidOperationException("Selector state is uninitialized");
        ulong count = ReadWord(checked(pointer + offset));
        if (count > 4096) throw new InvalidDataException("Selector count outside audited bounds");
        return count;
    }

    internal string Observe()
    {
        ulong plugins = Counter(profile.PluginsRva, profile.PluginsCountOffset);
        ulong keywords = Counter(profile.KeywordsRva, profile.KeywordsCountOffset);
        return plugins.ToString(CultureInfo.InvariantCulture) + ":" + keywords.ToString(CultureInfo.InvariantCulture);
    }
}
