using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

// Only the batch-logon right can be changed. The operator owns authorization and
// the durable ownership journal; none of this API is exposed through SSH.
public static class ValidationLogonRights {
    public const string Batch = "SeBatchLogonRight";
    [StructLayout(LayoutKind.Sequential)]
    private struct Attributes {
        public uint Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Flags;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString {
        public ushort Length, MaximumLength;
        public IntPtr Buffer;
    }
    [DllImport("advapi32.dll")]
    private static extern uint LsaOpenPolicy(IntPtr system, ref Attributes attributes, uint access, out IntPtr policy);
    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policy);
    [DllImport("advapi32.dll")]
    private static extern uint LsaNtStatusToWinError(uint status);
    [DllImport("advapi32.dll")]
    private static extern uint LsaFreeMemory(IntPtr buffer);
    [DllImport("advapi32.dll")]
    private static extern uint LsaEnumerateAccountRights(IntPtr policy, byte[] sid, out IntPtr rights, out uint count);
    [DllImport("advapi32.dll")]
    private static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, UnicodeString[] rights, uint count);
    [DllImport("advapi32.dll")]
    private static extern uint LsaRemoveAccountRights(IntPtr policy, byte[] sid, [MarshalAs(UnmanagedType.U1)] bool all,
        UnicodeString[] rights, uint count);

    private static void Check(uint status) {
        if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status));
    }
    private static IntPtr Open(bool write) {
        var attributes = new Attributes { Length = (uint)Marshal.SizeOf(typeof(Attributes)) };
        IntPtr handle;
        Check(LsaOpenPolicy(IntPtr.Zero, ref attributes, write ? 0x810u : 0x800u, out handle));
        return handle;
    }
    private static byte[] Sid(string identity) {
        var sid = new SecurityIdentifier(identity);
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        return bytes;
    }
    public static string[] Read(string identity) {
        IntPtr policy = Open(false), buffer = IntPtr.Zero;
        try {
            uint count;
            uint status = LsaEnumerateAccountRights(policy, Sid(identity), out buffer, out count);
            if (LsaNtStatusToWinError(status) == 2) return new string[0];
            Check(status);
            if (count > 256) throw new InvalidOperationException("Unexpected account-right count");
            var result = new string[count];
            int size = Marshal.SizeOf(typeof(UnicodeString));
            for (int i = 0; i < result.Length; i++) {
                var item = (UnicodeString)Marshal.PtrToStructure(IntPtr.Add(buffer, i * size), typeof(UnicodeString));
                if (item.Buffer == IntPtr.Zero || item.Length % 2 != 0 || item.Length > item.MaximumLength)
                    throw new InvalidOperationException("Invalid account-right record");
                result[i] = Marshal.PtrToStringUni(item.Buffer, item.Length / 2);
            }
            Array.Sort(result, StringComparer.Ordinal);
            return result;
        } finally {
            if (buffer != IntPtr.Zero) LsaFreeMemory(buffer);
            LsaClose(policy);
        }
    }
    public static void SetBatch(string identity, bool enabled) {
        IntPtr policy = Open(true), buffer = Marshal.StringToHGlobalUni(Batch);
        try {
            var rights = new[] { new UnicodeString { Buffer = buffer,
                Length = (ushort)(Batch.Length * 2), MaximumLength = (ushort)((Batch.Length + 1) * 2) } };
            Check(enabled ? LsaAddAccountRights(policy, Sid(identity), rights, 1) :
                LsaRemoveAccountRights(policy, Sid(identity), false, rights, 1));
        } finally { Marshal.FreeHGlobal(buffer); LsaClose(policy); }
    }
}
