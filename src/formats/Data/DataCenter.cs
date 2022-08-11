using Vezel.Novadrop.Data.Nodes;
using Vezel.Novadrop.Data.Serialization;
using Vezel.Novadrop.Data.Serialization.Readers;

namespace Vezel.Novadrop.Data;

public static class DataCenter
{
    public static ReadOnlyMemory<byte> LatestKey { get; } = new byte[]
    {
        0x1c, 0x01, 0xc9, 0x04, 0xff, 0x76, 0xff, 0x06,
        0xc2, 0x11, 0x18, 0x7e, 0x19, 0x7b, 0x57, 0x16,
    };

    public static ReadOnlyMemory<byte> LatestIV { get; } = new byte[]
    {
        0x39, 0x6c, 0x34, 0x2c, 0x52, 0xa0, 0xc1, 0x2d,
        0x51, 0x1d, 0xd0, 0x20, 0x9f, 0x90, 0xca, 0x7d,
    };

    public static int LatestRevision => 387463;

    [SuppressMessage("", "CA5358")]
    internal static Aes CreateCipher(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> iv)
    {
        var aes = Aes.Create();

        aes.Mode = CipherMode.CFB;
        aes.Padding = PaddingMode.None;
        aes.FeedbackSize = 128;
        aes.Key = key.ToArray();
        aes.IV = iv.ToArray();

        return aes;
    }

    public static DataCenterNode Create()
    {
        return new UserDataCenterNode(null, DataCenterConstants.RootNodeName);
    }

    public static Task<DataCenterNode> LoadAsync(
        Stream stream, DataCenterLoadOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        _ = stream.CanRead ? true : throw new ArgumentException(null, nameof(stream));
        ArgumentNullException.ThrowIfNull(options);

        DataCenterReader reader = (options.Mode, options.Mutability) switch
        {
            (DataCenterLoaderMode.Transient, not DataCenterMutability.Mutable) =>
                new TransientDataCenterReader(options),
            (DataCenterLoaderMode.Lazy, DataCenterMutability.Immutable) => new LazyImmutableDataCenterReader(options),
            (DataCenterLoaderMode.Lazy, _) => new LazyMutableDataCenterReader(options),
            (DataCenterLoaderMode.Eager, DataCenterMutability.Immutable) => new EagerImmutableDataCenterReader(options),
            (DataCenterLoaderMode.Eager, _) => new EagerMutableDataCenterReader(options),
            _ => throw new ArgumentException(null, nameof(options)),
        };

        return reader.ReadAsync(stream, cancellationToken);
    }

    public static Task SaveAsync(
        DataCenterNode root,
        Stream stream,
        DataCenterSaveOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(stream);
        _ = stream.CanWrite ? true : throw new ArgumentException(null, nameof(stream));
        ArgumentNullException.ThrowIfNull(options);

        return new DataCenterWriter(options).WriteAsync(stream, root, cancellationToken);
    }
}
