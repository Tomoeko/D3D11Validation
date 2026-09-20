// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Text;

static class TestSelectorProfile
{
    static byte[] Valid()
    {
        var data = new byte[72];
        Array.Copy(Encoding.ASCII.GetBytes("DVSEL001"), data, 8);
        for (int i = 8; i < 40; ++i) data[i] = 0xab;
        Array.Copy(BitConverter.GetBytes((ulong)4096), 0, data, 40, 8);
        Array.Copy(BitConverter.GetBytes((ulong)16), 0, data, 48, 8);
        Array.Copy(BitConverter.GetBytes((ulong)8192), 0, data, 56, 8);
        Array.Copy(BitConverter.GetBytes((ulong)24), 0, data, 64, 8);
        return data;
    }

    static void Rejected(byte[] data)
    {
        try { new SelectorObservation.Profile(data); }
        catch (InvalidDataException) { return; }
        throw new Exception("Invalid selector profile accepted");
    }

    static void Main()
    {
        var profile = new SelectorObservation.Profile(Valid());
        if (profile.PluginsRva != 4096 || profile.KeywordsRva != 8192 ||
            profile.PluginsCountOffset != 16 || profile.KeywordsCountOffset != 24 ||
            profile.ImageHash != "abababababababababababababababababababababababababababababababab")
            throw new Exception("Profile interpretation differs");
        Rejected(null);
        Rejected(new byte[71]);
        Rejected(new byte[73]);
        var data = Valid(); data[0] ^= 1; Rejected(data);
        data = Valid(); Array.Clear(data, 8, 32); Rejected(data);
        int checks = 6;
        foreach (int offset in new[] {40, 56})
            foreach (ulong value in new ulong[] {0, 4095, 4097, uint.MaxValue - 7UL, ulong.MaxValue})
            {
                data = Valid(); Array.Copy(BitConverter.GetBytes(value), 0, data, offset, 8);
                Rejected(data); checks++;
            }
        foreach (int offset in new[] {48, 64})
            foreach (ulong value in new ulong[] {0, 1, 9, 264, ulong.MaxValue})
            {
                data = Valid(); Array.Copy(BitConverter.GetBytes(value), 0, data, offset, 8);
                Rejected(data); checks++;
            }
        data = Valid(); Array.Copy(data, 40, data, 56, 8); Rejected(data); checks++;
        Console.WriteLine("PASS: " + checks + " selector profile checks; no native memory access");
    }
}
