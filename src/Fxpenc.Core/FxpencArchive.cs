using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LPGXP.Archive;

/// <summary>
/// FXPENC v1 encrypted package reader/writer.
/// Uses AES-256-GCM and a 32-byte game-specific key.
/// </summary>
public static class FxpencArchive
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("FXPENC\r\n");
    private const byte Version = 1;
    private const int KeyLength = 32;
    private const int NoncePrefixLength = 8;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int DefaultChunkSize = 1024 * 1024;
    private const int MinimumChunkSize = 4096;
    private const int MaximumChunkSize = 16 * 1024 * 1024;
    private const int MaximumManifestLength = 64 * 1024 * 1024;

    private sealed record Entry(string Path, long Length, int Chunks);
    private sealed record Manifest(int Version, int ChunkSize, List<Entry> Entries);
    public sealed record ArchiveEntry(string Path, long Length, int Chunks);
    private sealed record Header(Manifest Manifest, byte[] NoncePrefix);

    public static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(KeyLength);

    public static IReadOnlyList<ArchiveEntry> List(string archivePath, byte[] key)
    {
        using var stream = File.OpenRead(archivePath);
        Header header = ReadHeader(stream, key);
        return header.Manifest.Entries
            .Select(e => new ArchiveEntry(e.Path, e.Length, e.Chunks))
            .ToArray();
    }

    public static void PackDirectory(string inputDirectory, string outputArchive, byte[] key,
        int chunkSize = DefaultChunkSize)
    {
        ValidateKey(key);
        if (chunkSize < MinimumChunkSize || chunkSize > MaximumChunkSize)
            throw new ArgumentOutOfRangeException(nameof(chunkSize), "Chunk size must be between 4 KiB and 16 MiB.");

        string source = Path.GetFullPath(inputDirectory);
        if (!Directory.Exists(source))
            throw new DirectoryNotFoundException($"Input directory not found: {source}");

        string output = Path.GetFullPath(outputArchive);
        string sourcePrefix = source.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (output.StartsWith(sourcePrefix, PathComparison))
            throw new InvalidOperationException("Output archive must not be inside the source directory.");

        var files = Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories)
            .Select(full => (FullPath: full, RelativePath: Path.GetRelativePath(source, full).Replace('\\', '/')))
            .OrderBy(x => x.RelativePath, StringComparer.Ordinal)
            .ToList();

        var entries = new List<Entry>(files.Count);
        foreach (var file in files)
        {
            ValidateArchivePath(file.RelativePath);
            long length = new System.IO.FileInfo(file.FullPath).Length;
            long chunks = length == 0 ? 0 : (length + chunkSize - 1) / chunkSize;
            if (chunks > int.MaxValue)
                throw new InvalidDataException($"Too many chunks in {file.RelativePath}.");
            entries.Add(new Entry(file.RelativePath, length, (int)chunks));
        }

        byte[] manifestPlain = JsonSerializer.SerializeToUtf8Bytes(new Manifest(Version, chunkSize, entries));
        if (manifestPlain.Length > MaximumManifestLength)
            throw new InvalidDataException("FXPENC manifest is too large.");

        byte[] prefix = RandomNumberGenerator.GetBytes(NoncePrefixLength);
        byte[] manifestCipher = new byte[manifestPlain.Length];
        byte[] manifestTag = new byte[TagLength];
        using (var aes = new AesGcm(key, TagLength))
            aes.Encrypt(MakeNonce(prefix, 0), manifestPlain, manifestCipher, manifestTag, HeaderAad(Version, chunkSize));

        string? parent = Path.GetDirectoryName(output);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        string temp = output + ".tmp-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6));

        try
        {
            using (var destination = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                destination.Write(Magic);
                destination.WriteByte(Version);
                WriteInt32(destination, chunkSize);
                destination.Write(prefix);
                WriteInt32(destination, manifestCipher.Length);
                destination.Write(manifestCipher);
                destination.Write(manifestTag);

                uint counter = 1;
                byte[] buffer = new byte[chunkSize];
                for (int fileIndex = 0; fileIndex < files.Count; fileIndex++)
                {
                    var file = files[fileIndex];
                    Entry entry = entries[fileIndex];
                    using var input = new FileStream(file.FullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                    for (int chunkIndex = 0; chunkIndex < entry.Chunks; chunkIndex++)
                    {
                        int expected = (int)Math.Min(chunkSize, entry.Length - (long)chunkIndex * chunkSize);
                        ReadExactly(input, buffer, expected);
                        if (counter == uint.MaxValue)
                            throw new InvalidDataException("FXPENC v1 nonce counter limit exceeded.");
                        byte[] cipher = new byte[expected];
                        byte[] tag = new byte[TagLength];
                        using (var aes = new AesGcm(key, TagLength))
                            aes.Encrypt(MakeNonce(prefix, counter++), buffer.AsSpan(0, expected), cipher, tag,
                                ChunkAad(entry, chunkIndex, expected));
                        destination.Write(cipher);
                        destination.Write(tag);
                        CryptographicOperations.ZeroMemory(buffer.AsSpan(0, expected));
                    }
                    if (input.ReadByte() != -1)
                        throw new IOException($"File changed while packing: {file.RelativePath}");
                }
                destination.Flush(true);
            }
            File.Move(temp, output, true);
        }
        catch
        {
            try { File.Delete(temp); } catch { /* best-effort temporary-file cleanup */ }
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(manifestPlain);
        }
    }

    public static byte[] ReadFile(string archivePath, string entryPath, byte[] key)
    {
        ValidateKey(key);
        string wanted = NormalizeArchivePath(entryPath);
        using var stream = File.OpenRead(archivePath);
        Header header = ReadHeader(stream, key);
        Entry? selected = header.Manifest.Entries.FirstOrDefault(e => e.Path == wanted);
        if (selected is null) throw new FileNotFoundException($"Asset not found in archive: {wanted}");
        if (selected.Length > int.MaxValue)
            throw new IOException("Asset exceeds the byte-array limit; use ExtractDirectory for large files.");

        using var output = new MemoryStream((int)selected.Length);
        ReadPayload(stream, header, key, (entry, plain) =>
        {
            if (entry.Path == wanted) output.Write(plain);
        });
        return output.ToArray();
    }

    public static void ExtractDirectory(string archivePath, string outputDirectory, byte[] key)
    {
        ValidateKey(key);
        string root = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(root);
        string rootPrefix = root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        using var stream = File.OpenRead(archivePath);
        Header header = ReadHeader(stream, key);

        ReadPayload(stream, header, key, (entry, plain) =>
        {
            string target = Path.GetFullPath(Path.Combine(root, entry.Path.Replace('/', Path.DirectorySeparatorChar)));
            if (!target.StartsWith(rootPrefix, PathComparison))
                throw new InvalidDataException("Archive path escapes the extraction directory.");
            string? directory = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
            using var destination = new FileStream(target, FileMode.Append, FileAccess.Write, FileShare.None);
            destination.Write(plain);
        }, prepareTargets: true, outputRoot: root);
    }

    private static void ReadPayload(Stream stream, Header header, byte[] key, Action<Entry, byte[]> consume,
        bool prepareTargets = false, string? outputRoot = null)
    {
        uint counter = 1;
        foreach (Entry entry in header.Manifest.Entries)
        {
            string? target = null;
            if (prepareTargets)
            {
                target = Path.GetFullPath(Path.Combine(outputRoot!, entry.Path.Replace('/', Path.DirectorySeparatorChar)));
                string prefix = outputRoot!.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (!target.StartsWith(prefix, PathComparison))
                    throw new InvalidDataException("Archive path escapes the extraction directory.");
                string? parent = Path.GetDirectoryName(target);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                using var empty = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None);
            }

            for (int chunkIndex = 0; chunkIndex < entry.Chunks; chunkIndex++)
            {
                int length = (int)Math.Min(header.Manifest.ChunkSize,
                    entry.Length - (long)chunkIndex * header.Manifest.ChunkSize);
                byte[] cipher = ReadBytes(stream, length);
                byte[] tag = ReadBytes(stream, TagLength);
                byte[] plain = new byte[length];
                if (counter == uint.MaxValue)
                    throw new InvalidDataException("FXPENC v1 nonce counter limit exceeded.");
                try
                {
                    using var aes = new AesGcm(key, TagLength);
                    aes.Decrypt(MakeNonce(header.NoncePrefix, counter++), cipher, tag, plain,
                        ChunkAad(entry, chunkIndex, length));
                    consume(entry, plain);
                }
                catch (CryptographicException ex)
                {
                    throw new CryptographicException($"FXPENC authentication failed for {entry.Path} chunk {chunkIndex}.", ex);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                }
            }
        }

        if (stream.Position != stream.Length)
            throw new InvalidDataException("FXPENC archive contains trailing bytes.");
    }

    private static Header ReadHeader(Stream stream, byte[] key)
    {
        ValidateKey(key);
        if (stream.Length - stream.Position < 25 + TagLength)
            throw new InvalidDataException("File is too short to be an FXPENC archive.");
        if (!CryptographicOperations.FixedTimeEquals(ReadBytes(stream, Magic.Length), Magic))
            throw new InvalidDataException("Invalid FXPENC magic.");
        int version = stream.ReadByte();
        if (version != Version) throw new InvalidDataException($"Unsupported FXPENC version: {version}.");
        int chunkSize = ReadInt32(stream);
        if (chunkSize < MinimumChunkSize || chunkSize > MaximumChunkSize)
            throw new InvalidDataException("Invalid FXPENC chunk size.");
        byte[] prefix = ReadBytes(stream, NoncePrefixLength);
        int manifestLength = ReadInt32(stream);
        if (manifestLength < 2 || manifestLength > MaximumManifestLength ||
            stream.Length - stream.Position < (long)manifestLength + TagLength)
            throw new InvalidDataException("Invalid FXPENC manifest length.");

        byte[] cipher = ReadBytes(stream, manifestLength);
        byte[] tag = ReadBytes(stream, TagLength);
        byte[] plain = new byte[manifestLength];
        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(MakeNonce(prefix, 0), cipher, tag, plain, HeaderAad((byte)version, chunkSize));
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("Wrong FXPENC key or modified manifest.", ex);
        }

        try
        {
            Manifest manifest = JsonSerializer.Deserialize<Manifest>(plain)
                ?? throw new InvalidDataException("Empty FXPENC manifest.");
            if (manifest.Version != Version || manifest.ChunkSize != chunkSize || manifest.Entries is null)
                throw new InvalidDataException("Unsupported or inconsistent FXPENC manifest.");
            var paths = new HashSet<string>(StringComparer.Ordinal);
            ulong chunks = 1;
            foreach (Entry entry in manifest.Entries)
            {
                ValidateArchivePath(entry.Path);
                if (!paths.Add(entry.Path)) throw new InvalidDataException($"Duplicate archive path: {entry.Path}");
                if (entry.Length < 0 || entry.Chunks < 0) throw new InvalidDataException("Negative file metadata.");
                long expected = entry.Length == 0 ? 0 : (entry.Length + chunkSize - 1) / chunkSize;
                if (expected != entry.Chunks) throw new InvalidDataException($"Invalid chunk count for {entry.Path}");
                chunks += (uint)entry.Chunks;
            }
            if (chunks > uint.MaxValue) throw new InvalidDataException("FXPENC v1 nonce counter limit exceeded.");
            long payloadLength = 0;
            foreach (Entry entry in manifest.Entries)
                payloadLength = checked(payloadLength + entry.Length + (long)entry.Chunks * TagLength);
            if (stream.Length - stream.Position != payloadLength)
                throw new InvalidDataException("Payload size does not match the FXPENC manifest.");
            return new Header(manifest, prefix);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static byte[] HeaderAad(byte version, int chunkSize)
    {
        byte[] aad = new byte[5];
        aad[0] = version;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(1), chunkSize);
        return aad;
    }

    private static byte[] ChunkAad(Entry entry, int index, int length)
    {
        byte[] path = Encoding.UTF8.GetBytes(entry.Path);
        byte[] aad = new byte[4 + path.Length + 4 + 4 + 8];
        BinaryPrimitives.WriteInt32LittleEndian(aad, path.Length);
        path.CopyTo(aad, 4);
        int offset = 4 + path.Length;
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset), index);
        BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(offset + 4), length);
        BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(offset + 8), entry.Length);
        return aad;
    }

    private static byte[] MakeNonce(byte[] prefix, uint counter)
    {
        byte[] nonce = new byte[NonceLength];
        prefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(NoncePrefixLength), counter);
        return nonce;
    }

    private static void ValidateKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != KeyLength) throw new ArgumentException("FXPENC requires a 32-byte key.", nameof(key));
    }

    private static string NormalizeArchivePath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return path.Replace('\\', '/');
    }

    private static void ValidateArchivePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 4096 ||
            path.StartsWith('/') || path.Contains('\\') || path.Contains(':') ||
            path.Any(char.IsControl) ||
            path.Split('/').Any(p => p.Length == 0 || p == "." || p == ".."))
            throw new InvalidDataException($"Unsafe archive path: {path}");
    }

    private static int ReadInt32(Stream stream) => BinaryPrimitives.ReadInt32LittleEndian(ReadBytes(stream, 4));
    private static void WriteInt32(Stream stream, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
        stream.Write(buffer);
    }

    private static byte[] ReadBytes(Stream stream, int length)
    {
        byte[] result = new byte[length];
        ReadExactly(stream, result, length);
        return result;
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int length)
    {
        int offset = 0;
        while (offset < length)
        {
            int read = stream.Read(buffer, offset, length - offset);
            if (read == 0) throw new EndOfStreamException("Unexpected end of FXPENC archive.");
            offset += read;
        }
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}
