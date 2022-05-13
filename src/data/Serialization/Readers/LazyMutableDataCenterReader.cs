using Vezel.Novadrop.Data.Nodes;
using Vezel.Novadrop.Data.Serialization.Items;

namespace Vezel.Novadrop.Data.Serialization.Readers;

sealed class LazyMutableDataCenterReader : DataCenterReader
{
    public LazyMutableDataCenterReader(DataCenterLoadOptions options)
        : base(options)
    {
    }

    protected override LazyMutableDataCenterNode AllocateNode(
        DataCenterAddress address,
        DataCenterRawNode raw,
        object parent,
        string name,
        string? value,
        DataCenterKeys keys,
        CancellationToken cancellationToken)
    {
        LazyMutableDataCenterNode node = null!;

        return node = new LazyMutableDataCenterNode(
            parent,
            name,
            value,
            keys,
            () =>
            {
                var attributes = new OrderedDictionary<string, DataCenterValue>(raw.AttributeCount);

                ReadAttributes(raw, attributes, static (attributes, name, value) =>
                {
                    if (!attributes.TryAdd(name, value))
                        throw new InvalidDataException($"Attribute named '{name}' was already recorded earlier.");
                });

                return attributes;
            },
            () =>
            {
                var children = new List<DataCenterNode>(raw.ChildCount);

                ReadChildren(raw, node, children, static (children, node) => children.Add(node), default);

                return children;
            });
    }

    protected override LazyImmutableDataCenterNode? ResolveNode(
        DataCenterAddress address, object parent, CancellationToken cancellationToken)
    {
        return Unsafe.As<LazyImmutableDataCenterNode>(CreateNode(address, parent, default));
    }
}
