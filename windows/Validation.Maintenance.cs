// Trusted bootstrap helpers. No deployment-supplied assembly is loaded here.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

public static class ValidationMaintenance
{
    public static string ReadInput()
    {
        var read = System.Threading.Tasks.Task.Run(() => {
            using (var input = Console.OpenStandardInput())
            using (var memory = new MemoryStream())
            {
                var buffer = new byte[1024];
                int count;
                while ((count = input.Read(buffer, 0, buffer.Length)) != 0)
                {
                    if (memory.Length + count > 16384) throw new InvalidDataException("maintenance_input_size");
                    memory.Write(buffer, 0, count);
                }
                return new UTF8Encoding(false, true).GetString(memory.ToArray());
            }
        });
        if (!read.Wait(5000)) throw new TimeoutException("maintenance_input_timeout");
        return read.Result;
    }

    public static string Digest(byte[] bytes)
    {
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
    }

    public static void CheckMember(string name)
    {
        if (name == null || name.Length > 220 ||
            !Regex.IsMatch(name, @"\A[A-Za-z0-9_][A-Za-z0-9_./ -]*\z"))
            throw new InvalidDataException("maintenance_archive_path");
        var parts = name.Split('/');
        if (parts.Length < 2 || parts.Length > 16 ||
            !Regex.IsMatch(parts[0], @"\A(worker|unity-draw|unity-unhooked)-v[1-9][0-9]{0,8}\z"))
            throw new InvalidDataException("maintenance_archive_root");
        foreach (var part in parts)
            if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".") || part.EndsWith(" ") ||
                Regex.IsMatch(part, @"\A(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|\z)", RegexOptions.IgnoreCase))
                throw new InvalidDataException("maintenance_archive_path");
    }

    public static void CheckAncestors(string path)
    {
        for (var item = new DirectoryInfo(Path.GetDirectoryName(Path.GetFullPath(path))); item != null; item = item.Parent)
            if ((item.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("maintenance_reparse_path");
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("maintenance_reparse_path");
    }

    public static byte[] ReadSnapshot(string path, int limit)
    {
        CheckAncestors(path);
        // The parent is protected against renaming. FileShare.Read rejects an
        // existing writer and prevents writes/deletion while reading this handle.
        using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (file.Length > limit) throw new InvalidDataException("maintenance_input_size");
            var bytes = new byte[(int)file.Length];
            int offset = 0;
            while (offset < bytes.Length)
            {
                int count = file.Read(bytes, offset, bytes.Length - offset);
                if (count == 0) throw new EndOfStreamException();
                offset += count;
            }
            if (file.ReadByte() != -1) throw new InvalidDataException("maintenance_input_changed");
            return bytes;
        }
    }

    public static string[] Extract(string archivePath, string destination, string expectedSha256)
    {
        CheckAncestors(archivePath);
        CheckAncestors(destination);
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new IOException("maintenance_stage_exists");
        using (var file = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (file.Length > 268435456) throw new InvalidDataException("maintenance_archive_size");
            string actual;
            using (var sha = SHA256.Create())
                actual = BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "").ToLowerInvariant();
            if (actual != expectedSha256) throw new InvalidDataException("maintenance_archive_hash");
            file.Position = 0;
            using (var archive = new ZipArchive(file, ZipArchiveMode.Read, true))
            {
                if (archive.Entries.Count == 0 || archive.Entries.Count > 4096)
                    throw new InvalidDataException("maintenance_archive_count");
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var roots = new HashSet<string>(StringComparer.Ordinal);
                long total = 0;
                foreach (var entry in archive.Entries)
                {
                    CheckMember(entry.FullName);
                    int mode = (entry.ExternalAttributes >> 16) & 0xf000;
                    if ((mode != 0 && mode != 0x8000) || (entry.ExternalAttributes & 0x10) != 0 ||
                        entry.Length > 134217728 || !names.Add(entry.FullName))
                        throw new InvalidDataException("maintenance_archive_entry");
                    total = checked(total + entry.Length);
                    if (total > 536870912) throw new InvalidDataException("maintenance_expanded_size");
                    roots.Add(entry.FullName.Split('/')[0]);
                }
                foreach (var name in names)
                {
                    int separator = name.LastIndexOf('/');
                    while (separator >= 0)
                    {
                        if (names.Contains(name.Substring(0, separator)))
                            throw new InvalidDataException("maintenance_archive_file_directory_conflict");
                        separator = name.LastIndexOf('/', separator - 1);
                    }
                }
                // Validate the entire namespace before creating any extraction files.
                Directory.CreateDirectory(destination);
                foreach (var entry in archive.Entries)
                {
                    var target = Path.Combine(destination, entry.FullName.Replace('/', Path.DirectorySeparatorChar));
                    Directory.CreateDirectory(Path.GetDirectoryName(target));
                    using (var source = entry.Open())
                    using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        byte[] buffer = new byte[65536];
                        long copied = 0;
                        int count;
                        while ((count = source.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            copied = checked(copied + count);
                            if (copied > entry.Length) throw new InvalidDataException("maintenance_expanded_size");
                            output.Write(buffer, 0, count);
                        }
                        if (copied != entry.Length) throw new InvalidDataException("maintenance_truncated_entry");
                        output.Flush(true);
                    }
                }
                var result = new string[roots.Count];
                roots.CopyTo(result);
                Array.Sort(result, StringComparer.Ordinal);
                return result;
            }
        }
    }

    public static void Download(string address, int port, string ticket, string certificateSha256,
                                long expectedSize, string expectedSha256, string destination)
    {
        if (expectedSize < 1 || expectedSize > 268435456 || port < 1 || port > 65535 ||
            !Regex.IsMatch(ticket, @"\A[0-9a-f]{48}\z") || !Regex.IsMatch(certificateSha256, @"\A[0-9a-f]{64}\z"))
            throw new InvalidDataException("maintenance_download_parameters");
        System.Net.IPAddress ip;
        if (!System.Net.IPAddress.TryParse(address, out ip) || ip.AddressFamily != AddressFamily.InterNetwork ||
            ip.ToString() != address || ip.GetAddressBytes()[0] != 169 || ip.GetAddressBytes()[1] != 254)
            throw new InvalidDataException("maintenance_download_address");
        var timer = Stopwatch.StartNew();
        using (var socket = new TcpClient())
        {
            var connection = socket.ConnectAsync(ip, port);
            if (!connection.Wait(5000)) throw new TimeoutException("maintenance_connect_timeout");
            socket.ReceiveTimeout = 10000;
            socket.SendTimeout = 10000;
            using (var tls = new SslStream(socket.GetStream(), false,
                (sender, certificate, chain, errors) => certificate != null && Digest(certificate.GetRawCertData()) == certificateSha256))
            {
                tls.ReadTimeout = 10000;
                tls.WriteTimeout = 10000;
                tls.AuthenticateAsClient("d3d11-validation-deployment.invalid", null, SslProtocols.Tls12, false);
                var request = Encoding.ASCII.GetBytes("GET /" + ticket + "/deployment.zip HTTP/1.1\r\nHost: d3d11-validation-deployment.invalid\r\nConnection: close\r\n\r\n");
                tls.Write(request, 0, request.Length);
                var header = new List<byte>();
                while (true)
                {
                    if (timer.ElapsedMilliseconds > 120000 || header.Count >= 8192) throw new InvalidDataException("maintenance_http_header");
                    int value = tls.ReadByte();
                    if (value < 0 || value > 127) throw new InvalidDataException("maintenance_http_header");
                    header.Add((byte)value);
                    int n = header.Count;
                    if (n >= 4 && header[n-4] == 13 && header[n-3] == 10 && header[n-2] == 13 && header[n-1] == 10) break;
                }
                var lines = Encoding.ASCII.GetString(header.ToArray()).Split(new[] { "\r\n" }, StringSplitOptions.None);
                if (lines[0] != "HTTP/1.0 200 OK" && lines[0] != "HTTP/1.1 200 OK") throw new InvalidDataException("maintenance_http_status");
                int lengths = 0;
                for (int i = 1; i < lines.Length - 2; ++i)
                {
                    int colon = lines[i].IndexOf(':');
                    if (colon < 1 || char.IsWhiteSpace(lines[i][0])) throw new InvalidDataException("maintenance_http_header");
                    var key = lines[i].Substring(0, colon);
                    var value = lines[i].Substring(colon + 1).Trim();
                    if (key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
                        key.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("maintenance_http_encoding");
                    if (key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                    {
                        if (++lengths != 1 || value != expectedSize.ToString(System.Globalization.CultureInfo.InvariantCulture))
                            throw new InvalidDataException("maintenance_http_length");
                    }
                }
                if (lengths != 1) throw new InvalidDataException("maintenance_http_length");
                CheckAncestors(destination);
                using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var sha = SHA256.Create())
                {
                    var buffer = new byte[65536];
                    long remaining = expectedSize;
                    while (remaining > 0)
                    {
                        if (timer.ElapsedMilliseconds > 120000) throw new TimeoutException("maintenance_download_timeout");
                        int count = tls.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                        if (count == 0) throw new EndOfStreamException();
                        sha.TransformBlock(buffer, 0, count, buffer, 0);
                        output.Write(buffer, 0, count);
                        remaining -= count;
                    }
                    if (tls.ReadByte() != -1) throw new InvalidDataException("maintenance_http_trailing_content");
                    sha.TransformFinalBlock(new byte[0], 0, 0);
                    if (BitConverter.ToString(sha.Hash).Replace("-", "").ToLowerInvariant() != expectedSha256)
                        throw new InvalidDataException("maintenance_download_hash");
                    output.Flush(true);
                }
            }
        }
    }
}
