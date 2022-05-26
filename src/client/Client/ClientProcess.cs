namespace Vezel.Novadrop.Client;

public sealed class ClientProcess : GameProcess
{
    // Represents a TERA.exe process from the perspective of a Tl.exe-compatible process.

    public event Action? ServerListRequested;

    public event Action? AccountNameRequested;

    public event Action? TicketRequested;

    public event Action? LobbyEntered;

    public event Action<string>? WorldEntered;

    public event Action<GameEvent>? GameEventOccurred;

    public event Action<int>? GameExited;

    public event Action<string>? GameCrashed;

    public ClientProcessOptions Options { get; }

    public ClientProcess(ClientProcessOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        Options = options;
    }

    protected override void GetWindowConfiguration(out string className, out string windowName)
    {
        className = "LAUNCHER_CLASS";
        windowName = "LAUNCHER_WINDOW";
    }

    protected override void GetProcessConfiguration(out string fileName, out string[] arguments)
    {
        fileName = Options.FileName;
        arguments = Options.Language is string lang ? new[] { $"-LANGUAGEEXT={lang}" } : Array.Empty<string>();
    }

    protected override (nuint Id, ReadOnlyMemory<byte> Payload)? HandleWindowMessage(
        nuint id, ReadOnlySpan<byte> payload)
    {
        var opts = Options;
        var utf16 = Encoding.Unicode;

        (nuint, ReadOnlyMemory<byte>) HandleAccountNameRequest()
        {
            AccountNameRequested?.Invoke();

            return (2, Encoding.Unicode.GetBytes(opts.AccountName));
        }

        (nuint, ReadOnlyMemory<byte>) HandleTicketRequest()
        {
            TicketRequested?.Invoke();

            return (4, Encoding.UTF8.GetBytes(opts.Ticket));
        }

        (nuint, ReadOnlyMemory<byte>) HandleServerListRequest()
        {
            ServerListRequested?.Invoke();

            using var ms = new MemoryStream(ushort.MaxValue);

            var csl = new ProtoBufServerList
            {
                LastServerId = (uint)opts.LastServerId,
            };

            foreach (var (_, srv) in opts.Servers)
                csl.Servers.Add(new()
                {
                    Id = (uint)srv.Id,
                    Title = utf16.GetBytes(srv.Name),
                    Category = utf16.GetBytes(srv.Category),
                    Name = utf16.GetBytes(srv.Title),
                    Queue = utf16.GetBytes(srv.Queue),
                    Population = utf16.GetBytes(srv.Population),
                    Address = srv.Address is IPAddress addr
                        ? BinaryPrimitives.ReadUInt32BigEndian(addr.GetAddressBytes())
                        : 0,
                    Port = (uint)srv.Port,
                    Available = srv.IsAvailable ? 1u : 0,
                    UnavailableMessage = utf16.GetBytes(srv.UnavailableMessage),
                    Host = srv.Host is string host ? utf16.GetBytes(host) : null,
                });

            Serializer.Serialize(ms, csl);

            return (6, ms.ToArray());
        }

        (nuint, ReadOnlyMemory<byte>)? HandleEnterLobbyOrWorld(ReadOnlySpan<byte> payload)
        {
            if (payload.IsEmpty)
                LobbyEntered?.Invoke();
            else
                WorldEntered?.Invoke(utf16.GetString(payload)[..^1]); // Strip NUL terminator.

            return null;
        }

        (nuint, ReadOnlyMemory<byte>)? HandleGameEvent()
        {
            GameEventOccurred?.Invoke((GameEvent)id);

            return null;
        }

        (nuint, ReadOnlyMemory<byte>)? HandleGameExit(ReadOnlySpan<byte> payload)
        {
            GameExited?.Invoke(BinaryPrimitives.ReadInt32LittleEndian(payload[(sizeof(int) * 2)..sizeof(int)]));

            return null;
        }

        (nuint, ReadOnlyMemory<byte>)? HandleGameCrash(ReadOnlySpan<byte> payload)
        {
            GameCrashed?.Invoke(utf16.GetString(payload).Trim());

            return null;
        }

        return id switch
        {
            1 => HandleAccountNameRequest(),
            3 => HandleTicketRequest(),
            5 => HandleServerListRequest(),
            7 => HandleEnterLobbyOrWorld(payload),
            8 => null,
            10 => null,
            12 => null,
            19 => null,
            20 => null,
            21 => null,
            25 => null,
            26 => null,
            1000 => null,
            >= 1001 and <= 1016 => HandleGameEvent(),
            1020 => HandleGameExit(payload),
            1021 => HandleGameCrash(payload),
            1022 => null,
            1023 => null,
            1024 => null,
            1025 => null,
            1027 => null,
            _ => null,
        };
    }
}
