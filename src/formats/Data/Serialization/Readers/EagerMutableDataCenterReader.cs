using Vezel.Novadrop.Data.Nodes;
using Vezel.Novadrop.Data.Serialization.Items;

namespace Vezel.Novadrop.Data.Serialization.Readers;

sealed class EagerMutableDataCenterReader : DataCenterReader
{
    public EagerMutableDataCenterReader(DataCenterLoadOptions options)
        : base(options)
    {
    }

    protected override EagerMutableDataCenterNode AllocateNode(
        DataCenterAddress address,
        DataCenterRawNode raw,
        object parent,
        string name,
        string? value,
        DataCenterKeys keys,
        CancellationToken cancellationToken)
    {
        var attrCount = raw.AttributeCount - (value != null ? 1 : 0);
        var childCount = raw.ChildCount;
        var node = new EagerMutableDataCenterNode(parent, name, value, keys, attrCount, childCount);

        if (attrCount != 0)
            ReadAttributes(raw, node.Attributes, static (attributes, name, value) =>
            {
                if (!attributes.TryAdd(name, value))
                    throw new InvalidDataException($"Attribute named '{name}' was already recorded earlier.");
            });

        if (childCount != 0)
            ReadChildren(raw, node, node.Children, static (children, node) => children.Add(node), cancellationToken);

        return node;
    }

    protected override EagerMutableDataCenterNode? ResolveNode(
        DataCenterAddress address, object parent, CancellationToken cancellationToken)
    {
        return Unsafe.As<EagerMutableDataCenterNode>(CreateNode(address, parent, cancellationToken));
    }
}
