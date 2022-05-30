namespace Vezel.Novadrop.Data;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public abstract class DataCenterNode
{
    public DataCenter Owner => _parent is DataCenter dc ? dc : Unsafe.As<DataCenterNode>(_parent).Owner;

    public DataCenterNode? Parent => _parent is not DataCenter ? Unsafe.As<DataCenterNode>(_parent) : null;

    public string Name { get; }

    public virtual string? Value
    {
        get => _value;
        set => _value = value;
    }

    public virtual DataCenterKeys Keys
    {
        get => _keys;
        set
        {
            ArgumentNullException.ThrowIfNull(value);

            _keys = value;
        }
    }

    public abstract IReadOnlyDictionary<string, DataCenterValue> Attributes { get; }

    public virtual bool HasAttributes => Attributes.Count != 0;

    public abstract IReadOnlyList<DataCenterNode> Children { get; }

    public virtual bool HasChildren => Children.Count != 0;

    public abstract bool IsImmutable { get; }

    public DataCenterValue this[string name]
    {
        get => Attributes[name];
        set => SetAttribute(name, value);
    }

    readonly object _parent;

    string? _value;

    DataCenterKeys _keys;

    private protected DataCenterNode(object parent, string name, string? value, DataCenterKeys keys)
    {
        _parent = parent;
        Name = name;
        _value = value;
        _keys = keys;
    }

    public abstract DataCenterNode CreateChild(string name);

    public abstract DataCenterNode CreateChildAt(int index, string name);

    public abstract bool RemoveChild(DataCenterNode node);

    public abstract void RemoveChildAt(int index);

    public abstract void RemoveChildRange(int index, int count);

    public abstract void ClearChildren();

    public void ReverseChildren()
    {
        ReverseChildren(0, Children.Count);
    }

    public abstract void ReverseChildren(int index, int count);

    public abstract void SortChildren(IComparer<DataCenterNode> comparer);

    public abstract void AddAttribute(string name, DataCenterValue value);

    public abstract void SetAttribute(string name, DataCenterValue value);

    public abstract bool RemoveAttribute(string name);

    public abstract void ClearAttributes();

    public override string ToString()
    {
        return $"{{Name: {Name}, Value: {Value}, Keys: {Keys}, " +
            $"Attributes: [{Attributes.Count}], Children: [{Children.Count}]}}";
    }
}
