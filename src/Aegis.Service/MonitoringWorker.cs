using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Aegis.Core;

namespace Aegis.Service;

public sealed class MonitoringWorker : BackgroundService
{
    private readonly DetectionPipeline _pipeline;
    private readonly RuntimeState _state;
    private readonly RansomwareCanary _canary;
    private readonly ILogger<MonitoringWorker> _logger;
    private readonly Channel<Observation> _channel = Channel.CreateBounded<Observation>(new BoundedChannelOptions(2000)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true
    });
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly EventDeduplicator _debounce = new();
    private readonly EventDeduplicator _networkDebounce = new();
    private TraceEventSession? _session;
    private readonly TaskCompletionSource _etwLost = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? _processorTask;
    private Task? _etwTask;
    private volatile bool _etwActive;

    private static readonly Guid ProcessProvider = new("22FB2CD6-0E7B-422B-A0C7-72FAD1F8D607");
    private static readonly Guid NetworkProvider = new("7DD42A49-5329-4832-8DFD-43D979153A88");
    private static readonly Guid RegistryProvider = new("70EB4F03-C1DE-4F73-A051-33D13D5413BD");
    private static readonly Guid DnsProvider = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    public MonitoringWorker(DetectionPipeline pipeline, RuntimeState state, RansomwareCanary canary, ILogger<MonitoringWorker> logger)
    {
        _pipeline = pipeline;
        _state = state;
        _canary = canary;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _processorTask = Task.Run(() => ProcessQueueAsync(stoppingToken), stoppingToken);
        if (_canary.ManifestTampered)
        {
            _logger.LogWarning("El manifiesto de canarios no supera la comprobación de integridad local.");
            Enqueue(new Observation
            {
                Kind = EventKind.PersistenceChanged,
                Subject = _canary.ManifestPath,
                BehaviorFlags = ["canary_manifest_tampered"],
                Source = "canary-manifest"
            });
        }
        StartEtw(stoppingToken);
        StartFileWatchers();
        // El respaldo arranca solo si ETW no está disponible o se detiene.
        var fallback = StartProcessSnapshotAsync(stoppingToken);
        var canaryLoop = StartCanaryLoopAsync(stoppingToken);

        _state.MonitorActive = true;
        _logger.LogInformation("Aegis Guard monitorización activa. ETW={Etw}, watchers={Watchers}", _etwActive, _watchers.Count);

        await Task.WhenAll(_processorTask, fallback, canaryLoop, _etwTask ?? Task.CompletedTask).ConfigureAwait(false);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _state.MonitorActive = false;
        _channel.Writer.TryComplete();
        _etwLost.TrySetResult();
        // Drenar la cola antes de cerrar para no perder cuarentenas recientes.
        if (_processorTask is not null)
        {
            try { await _processorTask.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken).ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogDebug(ex, "No se pudo drenar completamente la cola"); }
        }
        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }
        _watchers.Clear();
        _session?.Dispose();
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task ProcessQueueAsync(CancellationToken ct)
    {
        await foreach (var observation in _channel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            try { await _pipeline.ProcessAsync(observation, ct).ConfigureAwait(false); }
            catch (Exception ex) { _logger.LogWarning(ex, "Error procesando observación {Id}", observation.Id); }
        }
    }

    private void StartEtw(CancellationToken ct)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        try
        {
            _session = new TraceEventSession("AegisGuard-Realtime");
            _session.EnableProvider(ProcessProvider, TraceEventLevel.Informational);
            _session.EnableProvider(NetworkProvider, TraceEventLevel.Informational);
            _session.EnableProvider(RegistryProvider, TraceEventLevel.Informational);
            _session.EnableProvider(DnsProvider, TraceEventLevel.Informational);
            _session.Source.Dynamic.All += OnTraceEvent;
            _etwActive = true;
            _state.EtwActive = true;
            _etwTask = Task.Run(() =>
            {
                try { _session!.Source.Process(); }
                catch (Exception ex) { _logger.LogWarning(ex, "Sesión ETW detenida"); }
                finally
                {
                    // Sin este aviso el fallback nunca arranca y la UI sigue
                    // diciendo "protegido" aunque no haya telemetría de procesos.
                    _etwActive = false;
                    _state.EtwActive = false;
                    _etwLost.TrySetResult();
                }
            }, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "No se pudo abrir ETW; se usa monitorización de respaldo");
            _etwActive = false;
            _state.EtwActive = false;
            _etwLost.TrySetResult();
        }
    }

    private void OnTraceEvent(TraceEvent data)
    {
        try
        {
            if (data.ProviderGuid == ProcessProvider && (int)data.ID == 1)
            {
                var image = GetString(data, "ImageName", "ImageFileName", "FileName");
                if (string.IsNullOrWhiteSpace(image)) return;
                Enqueue(new Observation
                {
                    Kind = EventKind.ProcessStarted,
                    Subject = image,
                    ProcessId = GetProcessId(data, "ProcessID", "ProcessId", "pid"),
                    // El provider entrega ParentID como PID numérico; resolverlo
                    // a imagen permite que unusual_parent funcione con telemetría real.
                    ParentProcess = ResolveParent(GetString(data, "ParentID", "ParentId", "ppid")),
                    Source = "etw-process"
                });
                return;
            }

            if (data.ProviderGuid == NetworkProvider)
            {
                var remote = GetNetworkAddress(data, "daddr", "RemoteAddress", "DestinationAddress");
                if (string.IsNullOrWhiteSpace(remote)) return;
                var remotePort = GetNetworkPort(data, "dport", "RemotePort", "DestinationPort");
                var protocol = GetString(data, "protocol", "Protocol");
                // Una conexión establecida genera miles de eventos ETW por minuto.
                // Se conserva un único registro por destino durante 10 segundos.
                var key = $"net:{remote}:{remotePort}:{protocol}";
                if (_networkDebounce.IsDuplicate(key, 10_000)) return;
                Enqueue(new Observation
                {
                    Kind = EventKind.NetworkConnection,
                    Subject = GetString(data, "ProcessPath", "ImageName", "Application") ?? "network",
                    ProcessId = GetProcessId(data, "PID", "ProcessID", "pid"),
                    RemoteAddress = remote,
                    RemotePort = remotePort,
                    LocalPort = GetNetworkPort(data, "sport", "LocalPort", "SourcePort"),
                    Protocol = protocol,
                    Source = "etw-network"
                });
                return;
            }

            if (data.ProviderGuid == RegistryProvider)
            {
                var key = GetString(data, "KeyName", "KeyPath", "Name");
                if (string.IsNullOrWhiteSpace(key) || !IsPersistenceKey(key)) return;
                Enqueue(new Observation
                {
                    Kind = EventKind.PersistenceChanged,
                    Subject = key,
                    BehaviorFlags = ["persistence_registry"],
                    Source = "etw-registry"
                });
                return;
            }

            if (data.ProviderGuid == DnsProvider)
            {
                var domain = GetString(data, "QueryName", "Name", "Query");
                if (string.IsNullOrWhiteSpace(domain) || domain.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase)) return;
                Enqueue(new Observation
                {
                    Kind = EventKind.DnsQuery,
                    Subject = domain,
                    ProcessId = GetProcessId(data, "ProcessId", "ProcessID", "pid"),
                    Source = "etw-dns"
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "No se pudo interpretar evento ETW {EventId}", data.ID);
        }
    }

    private void StartFileWatchers()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var dirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(profile, "Downloads"),
            Path.GetTempPath()
        }.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d)).Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var dir in dirs)
        {
            try
            {
                var watcher = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    InternalBufferSize = 64 * 1024
                };
                watcher.Created += OnFileEvent;
                watcher.Changed += OnFileEvent;
                watcher.Deleted += OnFileEvent;
                watcher.Renamed += (_, e) => OnFileEvent(this, new FileSystemEventArgs(WatcherChangeTypes.Created, Path.GetDirectoryName(e.FullPath) ?? string.Empty, e.Name ?? string.Empty));
                watcher.Error += (_, e) => _logger.LogDebug(e.GetException(), "Error en FileSystemWatcher");
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex) { _logger.LogWarning(ex, "No se pudo vigilar {Dir}", dir); }
        }
    }

    private void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        if (!IsInterestingFile(e.FullPath)) return;
        if (_debounce.IsDuplicate(e.FullPath, 1500)) return;

        if (_canary.IsCanary(e.FullPath))
        {
            if (!_canary.WasModified(e.FullPath)) return;
            Enqueue(new Observation
            {
                Kind = EventKind.FileModified,
                Subject = e.FullPath,
                BehaviorFlags = ["ransomware_canary_modified"],
                Source = "canary"
            });
            return;
        }

        if (e.ChangeType == WatcherChangeTypes.Deleted) return;
        Enqueue(new Observation
        {
            Kind = e.ChangeType == WatcherChangeTypes.Created ? EventKind.FileCreated : EventKind.FileModified,
            Subject = e.FullPath,
            Source = "filesystem"
        });
    }

    private async Task StartProcessSnapshotAsync(CancellationToken ct)
    {
        if (_etwActive)
        {
            using var registration = ct.Register(() => _etwLost.TrySetResult());
            await _etwLost.Task.ConfigureAwait(false);
            if (ct.IsCancellationRequested) return;
            _logger.LogWarning("ETW no disponible: activada monitorización de procesos por sondeo");
        }

        var known = new HashSet<int>();
        try
        {
            var initial = Process.GetProcesses();
            try { known = initial.Select(p => p.Id).ToHashSet(); }
            finally { foreach (var p in initial) p.Dispose(); }
        }
        catch (Exception ex) { _logger.LogDebug(ex, "No se pudo tomar la instantánea inicial de procesos"); }

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(3));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            Process[] current = [];
            try
            {
                current = Process.GetProcesses();
                var currentIds = new HashSet<int>();
                foreach (var p in current)
                {
                    try { currentIds.Add(p.Id); }
                    catch { /* proceso terminado durante la enumeración */ }
                }
                foreach (var id in currentIds.Except(known))
                {
                    var p = current.FirstOrDefault(x => x.Id == id);
                    if (p is null) continue;
                    try
                    {
                        Enqueue(new Observation
                        {
                            Kind = EventKind.ProcessStarted,
                            Subject = p.MainModule?.FileName ?? p.ProcessName,
                            ProcessId = id.ToString(CultureInfo.InvariantCulture),
                            ParentProcess = "unknown",
                            Source = "process-snapshot"
                        });
                    }
                    catch { /* proceso protegido */ }
                }
                known = currentIds;
            }
            catch (Exception ex)
            {
                // Un error al enumerar no debe derribar el BackgroundService.
                _logger.LogDebug(ex, "Error en sondeo de procesos");
            }
            finally
            {
                foreach (var p in current) p.Dispose();
            }
        }
    }

    private async Task StartCanaryLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            foreach (var path in _canary.Paths)
            {
                // WasModified marca el canary como ya alertado: evita una nueva
                // amenaza cada 10 s mientras el fichero siga cifrado o borrado.
                if (!_canary.WasModified(path)) continue;
                Enqueue(new Observation
                {
                    Kind = EventKind.FileModified,
                    Subject = path,
                    BehaviorFlags = ["ransomware_canary_modified"],
                    Source = "canary-loop"
                });
            }
        }
    }

    private void Enqueue(Observation observation)
    {
        // Contar solo lo que entró realmente en el canal: DropOldest descarta
        // eventos bajo ráfaga y el KPI debe reflejarlo.
        if (_channel.Writer.TryWrite(observation)) Interlocked.Increment(ref _state.EventsTotal);
        else Interlocked.Increment(ref _state.DroppedEvents);
    }

    private static string? ResolveParent(string? parent)
    {
        if (!int.TryParse(parent, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid) || pid <= 0)
            return parent;
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.MainModule?.FileName ?? process.ProcessName;
        }
        catch
        {
            return pid.ToString(CultureInfo.InvariantCulture);
        }
    }

    private static string? GetString(TraceEvent data, params string[] names) =>
        GetPayload(data, names)?.ToString() is { Length: > 0 } value ? value : null;

    /// <summary>
    /// El provider de DNS no expone el PID en el payload; se toma del encabezado ETW.
    /// </summary>
    private static string? GetProcessId(TraceEvent data, params string[] names) =>
        GetString(data, names) ?? (data.ProcessID > 0
            ? data.ProcessID.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : null);

    private static object? GetPayload(TraceEvent data, params string[] names)
    {
        foreach (var name in names)
        {
            try
            {
                var value = data.PayloadByName(name);
                if (value is not null) return value;
            }
            catch { /* la propiedad no existe en esta versión de Windows */ }
        }
        return null;
    }

    /// <summary>
    /// ETW entrega las direcciones IPv4 como Int32/UInt32 little-endian:
    /// 16777343 (0x0100007F) es 127.0.0.1 y 234924224 (0x0E00A8C0) es 192.168.0.14.
    /// IPAddress.TryParse con un número suelto lo interpreta como big-endian,
    /// por lo que solo se usa cuando la cadena contiene puntos o dos puntos.
    /// </summary>
    private static string? GetNetworkAddress(TraceEvent data, params string[] names) =>
        TelemetryAddress.Normalize(GetPayload(data, names));

    private static string? GetNetworkPort(TraceEvent data, params string[] names) =>
        TelemetryAddress.NormalizePort(GetPayload(data, names));

    private static bool IsInterestingFile(string path)
    {
        var ext = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
        return ext is "exe" or "dll" or "sys" or "scr" or "com" or "msi" or "msp" or "ps1" or "bat" or "cmd" or "vbs" or "js" or "jse" or "hta" or "lnk" or "docm" or "xlsm" or "pptm" or "iso" or "img" or "jar";
    }

    private static bool IsPersistenceKey(string key) =>
        key.Contains(@"\Software\Microsoft\Windows\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase) ||
        key.Contains(@"\Software\Microsoft\Windows\CurrentVersion\RunOnce", StringComparison.OrdinalIgnoreCase) ||
        key.Contains(@"\System\CurrentControlSet\Services", StringComparison.OrdinalIgnoreCase) ||
        key.Contains(@"\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", StringComparison.OrdinalIgnoreCase) ||
        key.Contains(@"\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", StringComparison.OrdinalIgnoreCase);
}
