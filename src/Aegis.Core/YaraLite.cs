using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Aegis.Core;

/// <summary>
/// Subset de reglas YARA para el motor local. Soporta cadenas ASCII/UTF-16LE,
/// patrones hexadecimales con comodines, condiciones 'any/all/N of them' con
/// listas y paréntesis, tamaño de fichero, bytes mágicos y hash SHA-256 exacto.
/// El análisis se hace por bloques: no se limita a los primeros 8 MiB.
/// Las reglas no ejecutan código y tienen un límite de tamaño y patrones.
/// </summary>
public sealed class YaraLiteEngine
{
    private const int MaxRuleFileBytes = 512 * 1024;
    private const int MaxPatternsPerRule = 64;
    private const int ScanChunkBytes = 256 * 1024;
    private const int OverlapBytes = 8 * 1024;
    private const long MaxScanBytes = 512L * 1024 * 1024;

    private readonly List<YaraLiteRule> _rules = [];
    private readonly object _gate = new();

    public int RuleCount { get { lock (_gate) return _rules.Count; } }

    public int LoadDirectory(string directory)
    {
        if (!Directory.Exists(directory)) return 0;
        var loaded = 0;
        foreach (var file in Directory.EnumerateFiles(directory, "*.yar", SearchOption.TopDirectoryOnly)
                     .Concat(Directory.EnumerateFiles(directory, "*.yara", SearchOption.TopDirectoryOnly)))
        {
            try
            {
                if (new FileInfo(file).Length > MaxRuleFileBytes) continue;
                var rules = Parse(File.ReadAllText(file));
                lock (_gate) _rules.AddRange(rules);
                loaded += rules.Count;
            }
            catch (Exception ex) when (ex is FormatException or IOException or UnauthorizedAccessException)
            {
                // Una regla mal formada no detiene el motor ni el arranque.
            }
        }
        return loaded;
    }

    public List<YaraLiteRule> Parse(string source)
    {
        var result = new List<YaraLiteRule>();

        foreach (var (name, body) in ExtractRuleBlocks(source))
        {
            var rule = new YaraLiteRule { Name = name, Id = name };

            var meta = Regex.Match(body, @"meta\s*:(?<v>.*?)(?=\bstrings\s*:|\bcondition\s*:)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            if (meta.Success)
            {
                var severity = Regex.Match(meta.Groups["v"].Value, @"severity\s*=\s*""?(?<v>[a-z]+)""?", RegexOptions.IgnoreCase);
                if (severity.Success) rule.Severity = ParseSeverity(severity.Groups["v"].Value);
                var desc = Regex.Match(meta.Groups["v"].Value, @"description\s*=\s*""(?<v>[^""]+)""", RegexOptions.IgnoreCase);
                if (desc.Success) rule.Description = desc.Groups["v"].Value;
                var hash = Regex.Match(meta.Groups["v"].Value, @"sha256\s*=\s*""(?<v>[a-fA-F0-9]{64})""", RegexOptions.IgnoreCase);
                if (hash.Success) rule.Sha256 = hash.Groups["v"].Value.ToLowerInvariant();
            }

            var stringsSection = Regex.Match(body, @"strings\s*:(?<v>.*?)(?=\bcondition\s*:)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            if (stringsSection.Success)
            {
                // Las secuencias hexadecimales pueden ocupar varias líneas y
                // contener comentarios; capturarlas completas evita perder reglas.
                foreach (Match line in Regex.Matches(stringsSection.Groups["v"].Value,
                             @"(?ms)^\s*\$(?<id>[A-Za-z0-9_]+)\s*=\s*(?<expr>""[^""]*""|\{[^}]*\}|[^\r\n]+?)(?<mods>(?:\s+(?:nocase|wide|fullword|private))+)?\s*$"))
                {
                    if (rule.Patterns.Count >= MaxPatternsPerRule) break;
                    var value = line.Groups["expr"].Value.Trim();
                    var modifiers = line.Groups["mods"].Value
                        .Split([' ', '\t', '/'], StringSplitOptions.RemoveEmptyEntries)
                        .Select(x => x.Trim().ToLowerInvariant()).ToArray();
                    if (value.StartsWith('"') && value.EndsWith('"'))
                        rule.Patterns.Add(YaraPattern.FromText(line.Groups["id"].Value, value[1..^1], modifiers));
                    else if (value.StartsWith('{') && value.EndsWith('}'))
                        rule.Patterns.Add(YaraPattern.FromHex(line.Groups["id"].Value, value[1..^1]));
                    else
                        throw new FormatException($"Patrón no soportado en {rule.Name}: {line.Groups["id"].Value}");
                }
            }

            var condition = Regex.Match(body, @"condition\s*:(?<v>.*)", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            if (!condition.Success || string.IsNullOrWhiteSpace(condition.Groups["v"].Value))
                throw new FormatException($"Regla {rule.Name} sin condición");
            rule.Condition = condition.Groups["v"].Value.Trim();

            // Rechazar números desbordados al cargar: nunca deben lanzar desde
            // el escáner y hacer perder el evento que se está procesando.
            var numericText = Regex.Replace(rule.Condition, @"""[^""]*""", string.Empty);
            foreach (Match number in Regex.Matches(numericText, @"\d+"))
                if (!long.TryParse(number.Value, NumberStyles.None, CultureInfo.InvariantCulture, out _))
                    throw new FormatException($"Número no válido en {rule.Name}");

            result.Add(rule);
        }
        return result;
    }

    public int LoadRules(string source)
    {
        var rules = Parse(source);
        lock (_gate) _rules.AddRange(rules);
        return rules.Count;
    }

    public async Task<List<RuleMatch>> ScanFileAsync(string path, string? knownSha256 = null, CancellationToken ct = default)
    {
        List<YaraLiteRule> snapshot;
        lock (_gate) snapshot = [.. _rules];
        if (snapshot.Count == 0) return [];

        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists || fileInfo.Length > MaxScanBytes) return [];

        var hits = snapshot.Select(r => new bool[r.Patterns.Count]).ToArray();
        var needHash = knownSha256 is null || snapshot.Any(r =>
            r.Sha256 is not null || r.Condition.Contains("hash.sha256", StringComparison.OrdinalIgnoreCase));
        using var sha = needHash ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256) : null;
        byte[] head = [];
        byte[] carry = [];
        var buffer = new byte[ScanChunkBytes];

        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                   FileShare.ReadWrite | FileShare.Delete, buffer.Length,
                   FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            int read;
            while ((read = await fs.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false)) > 0)
            {
                ct.ThrowIfCancellationRequested();
                sha?.AppendData(buffer.AsSpan(0, read));
                if (head.Length == 0)
                    head = buffer.AsSpan(0, Math.Min(read, 8)).ToArray();

                var window = carry.Length == 0
                    ? buffer.AsSpan(0, read).ToArray()
                    : [.. carry, .. buffer.AsSpan(0, read)];

                for (var i = 0; i < snapshot.Count; i++)
                {
                    var patterns = snapshot[i].Patterns;
                    for (var j = 0; j < patterns.Count; j++)
                    {
                        if (!hits[i][j] && patterns[j].IsMatch(window)) hits[i][j] = true;
                    }
                }

                carry = window.AsSpan(Math.Max(0, window.Length - OverlapBytes)).ToArray();
            }
        }

        var actualHash = sha?.GetHashAndReset() is { } digest
            ? Convert.ToHexString(digest).ToLowerInvariant()
            : knownSha256;

        var matches = new List<RuleMatch>();
        for (var i = 0; i < snapshot.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var rule = snapshot[i];
            if (rule.Sha256 is not null &&
                !string.Equals(rule.Sha256, actualHash, StringComparison.OrdinalIgnoreCase)) continue;

            if (!EvaluateCondition(rule.Condition, hits[i], fileInfo.Length, actualHash, rule.Sha256,
                    head, rule.Patterns)) continue;

            matches.Add(new RuleMatch
            {
                RuleId = rule.Id,
                Name = string.IsNullOrWhiteSpace(rule.Description) ? rule.Name : rule.Description,
                Severity = rule.Severity,
                Evidence = rule.Patterns.Where((_, j) => hits[i][j]).Select(p => $"${p.Id}").ToList()
            });
        }
        return matches;
    }

    internal static bool EvaluateCondition(string condition, bool[] matches, long fileSize,
        string? actualHash, string? ruleHash, byte[]? head = null, IReadOnlyList<YaraPattern>? patterns = null)
    {
        var parser = new ConditionParser(condition, matches, fileSize, actualHash, ruleHash, head ?? [], patterns ?? []);
        return parser.ParseOr();
    }

    private sealed class ConditionParser(
        string condition, bool[] matches, long fileSize, string? actualHash,
        string? ruleHash, byte[] head, IReadOnlyList<YaraPattern> patterns)
    {
        private readonly string _text = ReplacePatternIds(condition, patterns);
        private int _pos;

        public bool ParseOr()
        {
            var value = ParseAnd();
            while (TryKeyword("or"))
            {
                var right = ParseAnd();
                value = value || right;
            }
            return value;
        }

        private bool ParseAnd()
        {
            var value = ParseTerm();
            while (TryKeyword("and"))
            {
                var right = ParseTerm();
                value = value && right;
            }
            return value;
        }

        private bool ParseTerm()
        {
            if (TryChar('('))
            {
                var value = ParseOr();
                if (!TryChar(')')) throw new FormatException("Paréntesis sin cerrar en la condición");
                return value;
            }
            if (TryKeyword("not")) return !ParseTerm();

            SkipWhitespace();
            var start = _pos;
            var nestedParentheses = 0;
            while (_pos < _text.Length)
            {
                // ')' de uint16(0) pertenece a la cláusula; solo termina la
                // cláusula el paréntesis que cierra un grupo de la condición.
                if (_text[_pos] == '(') nestedParentheses++;
                if (_text[_pos] == ')')
                {
                    if (nestedParentheses == 0) break;
                    nestedParentheses--;
                }
                if (char.IsWhiteSpace(_text[_pos]))
                {
                    var save = _pos;
                    SkipWhitespace();
                    if (KeywordAt("and") || KeywordAt("or")) { _pos = save; break; }
                    continue;
                }
                _pos++;
            }
            var clause = _text[start.._pos].Trim();
            if (clause.Length == 0) throw new FormatException("Cláusula vacía en la condición");
            return EvaluateClause(clause);
        }

        private bool EvaluateClause(string raw)
        {
            var clause = Regex.Replace(raw, @"\s+", string.Empty).ToLowerInvariant();
            if (clause is "anyofthem") return matches.Length > 0 && matches.Any(x => x);
            if (clause is "allofthem") return matches.Length > 0 && matches.All(x => x);

            var list = Regex.Match(clause, @"^(any|all)of\((?<ids>p\d+(?:,p\d+)*)\)$");
            if (list.Success)
            {
                var indexes = ParseIndexes(list.Groups["ids"].Value);
                return list.Groups[1].Value == "any"
                    ? indexes.Any(i => i < matches.Length && matches[i])
                    : indexes.Count > 0 && indexes.All(i => i < matches.Length && matches[i]);
            }

            var nOf = Regex.Match(clause, @"^(?<n>\d+)of(them|\((?<ids>p\d+(?:,p\d+)*)\))$");
            if (nOf.Success && int.TryParse(nOf.Groups["n"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var n))
            {
                var indexes = nOf.Groups["ids"].Success
                    ? ParseIndexes(nOf.Groups["ids"].Value)
                    : Enumerable.Range(0, matches.Length).ToList();
                return indexes.Count(i => i < matches.Length && matches[i]) >= n;
            }

            var pattern = Regex.Match(clause, @"^p(?<n>\d+)$");
            if (pattern.Success &&
                int.TryParse(pattern.Groups["n"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var index))
                return index < matches.Length && matches[index];

            var size = Regex.Match(clause, @"^filesize(?<op><=|>=|<|>)(?<n>\d+)$");
            if (size.Success && long.TryParse(size.Groups["n"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var limit))
                return size.Groups["op"].Value switch
                {
                    ">" => fileSize > limit,
                    ">=" => fileSize >= limit,
                    "<" => fileSize < limit,
                    "<=" => fileSize <= limit,
                    _ => false
                };

            var magic = Regex.Match(clause, @"^uint(?<bits>16|32)\((?<off>\d+)\)==0x(?<hex>[0-9a-f]+)$");
            if (magic.Success)
            {
                if (!int.TryParse(magic.Groups["off"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var offset))
                    return false;
                var width = magic.Groups["bits"].Value == "16" ? 2 : 4;
                if (offset < 0 || offset + width > head.Length) return false;
                var actualValue = magic.Groups["bits"].Value == "16"
                    ? BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(offset, 2))
                    : BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(offset, 4));
                return actualValue.ToString("x", CultureInfo.InvariantCulture) == magic.Groups["hex"].Value;
            }

            var hash = Regex.Match(clause, @"^hash\.sha256==""(?<h>[a-f0-9]{64})""$");
            if (hash.Success) return actualHash is not null &&
                                   string.Equals(hash.Groups["h"].Value, actualHash, StringComparison.OrdinalIgnoreCase) &&
                                   (ruleHash is null ||
                                    string.Equals(ruleHash, actualHash, StringComparison.OrdinalIgnoreCase));

            return false;
        }

        private static List<int> ParseIndexes(string value) =>
            value.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(x => int.TryParse(x.TrimStart('p'), NumberStyles.None, CultureInfo.InvariantCulture, out var i) ? i : -1)
                .Where(i => i >= 0).ToList();

        private static string ReplacePatternIds(string condition, IReadOnlyList<YaraPattern> patterns)
        {
            var text = condition;
            // De la más larga a la más corta para no romper $ab al reemplazar $a.
            foreach (var (pattern, index) in patterns.Select((p, i) => (p, i)).OrderByDescending(x => x.p.Id.Length))
                text = Regex.Replace(text, @"\$" + Regex.Escape(pattern.Id) + @"\b", $"P{index}", RegexOptions.IgnoreCase);
            return text;
        }

        private void SkipWhitespace()
        {
            while (_pos < _text.Length && char.IsWhiteSpace(_text[_pos])) _pos++;
        }

        private bool KeywordAt(string word)
        {
            if (_pos + word.Length > _text.Length) return false;
            if (!_text.AsSpan(_pos, word.Length).Equals(word, StringComparison.OrdinalIgnoreCase)) return false;
            var next = _pos + word.Length;
            return next == _text.Length || !char.IsLetterOrDigit(_text[next]);
        }

        private bool TryKeyword(string word)
        {
            var save = _pos;
            SkipWhitespace();
            if (KeywordAt(word))
            {
                _pos += word.Length;
                return true;
            }
            _pos = save;
            return false;
        }

        private bool TryChar(char c)
        {
            var save = _pos;
            SkipWhitespace();
            if (_pos < _text.Length && _text[_pos] == c)
            {
                _pos++;
                return true;
            }
            _pos = save;
            return false;
        }
    }

    /// <summary>
    /// Extrae cada bloque 'rule ... { ... }' contando llaves. Un regex no
    /// greedily hasta la primera línea con '}' rompe las secuencias hex
    /// multilínea y deja la regla sin condición.
    /// </summary>
    private static IEnumerable<(string Name, string Body)> ExtractRuleBlocks(string source)
    {
        var starts = new Regex(@"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        foreach (Match start in starts.Matches(source))
        {
            var depth = 1;
            var index = start.Index + start.Length;
            var inString = false;
            var escaped = false;
            for (; index < source.Length && depth > 0; index++)
            {
                var c = source[index];
                if (inString)
                {
                    if (escaped) { escaped = false; continue; }
                    if (c == '\\') { escaped = true; continue; }
                    if (c == '"') inString = false;
                    continue;
                }
                if (c == '"') { inString = true; continue; }
                if (c == '{') depth++;
                else if (c == '}') depth--;
            }
            if (depth != 0) throw new FormatException($"Regla {start.Groups[1].Value} sin cierre");
            yield return (start.Groups[1].Value, source[(start.Index + start.Length)..(index - 1)]);
        }
    }

    private static Severity ParseSeverity(string value) => value.ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        _ => Severity.Info
    };
}

public sealed class YaraLiteRule
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public Severity Severity { get; set; } = Severity.Medium;
    public string? Sha256 { get; set; }
    public string Condition { get; set; } = string.Empty;
    public List<YaraPattern> Patterns { get; } = [];
}

public sealed class YaraPattern
{
    public string Id { get; init; } = string.Empty;
    public byte[] Bytes { get; init; } = [];
    public bool[] Wildcards { get; init; } = [];
    public bool NoCase { get; init; }
    public bool Wide { get; init; }

    public static YaraPattern FromText(string id, string text, string[] modifiers) => new()
    {
        Id = id,
        Bytes = Encoding.UTF8.GetBytes(text),
        Wildcards = new bool[Encoding.UTF8.GetByteCount(text)],
        NoCase = modifiers.Contains("nocase", StringComparer.OrdinalIgnoreCase),
        Wide = modifiers.Contains("wide", StringComparer.OrdinalIgnoreCase)
    };

    public static YaraPattern FromHex(string id, string hex)
    {
        var tokens = Regex.Replace(hex, @"//.*$", "", RegexOptions.Multiline)
            .Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Where(t => !t.StartsWith("//", StringComparison.Ordinal))
            .ToArray();
        var bytes = new List<byte>();
        var wildcards = new List<bool>();
        foreach (var token in tokens)
        {
            if (token.All(c => c == '?'))
            {
                bytes.Add(0);
                wildcards.Add(true);
                continue;
            }
            var clean = token.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? token[2..] : token;
            if (clean.Length == 2 && byte.TryParse(clean, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
            {
                bytes.Add(b);
                wildcards.Add(false);
                continue;
            }
            // Un token no soportado acortaría el patrón y produciría falsos
            // positivos; se descarta la regla completa al cargar.
            throw new FormatException($"Token hexadecimal no soportado: {token}");
        }
        if (bytes.Count == 0) throw new FormatException("Patrón hexadecimal vacío");
        return new YaraPattern { Id = id, Bytes = [.. bytes], Wildcards = [.. wildcards] };
    }

    public bool IsMatch(ReadOnlySpan<byte> data)
    {
        if (Bytes.Length == 0 || data.Length < Bytes.Length) return false;
        for (var i = 0; i <= data.Length - Bytes.Length; i++)
        {
            if (MatchesAt(data, i, Bytes.Length, wildcardsByByte: j => Wildcards[j], byteAt: j => Bytes[j]))
                return true;
        }
        if (!Wide) return false;

        var wideLength = Bytes.Length * 2;
        if (data.Length < wideLength) return false;
        for (var i = 0; i <= data.Length - wideLength; i++)
        {
            if (MatchesAt(data, i, wideLength,
                    wildcardsByByte: j => Wildcards[j / 2],
                    byteAt: j => j % 2 == 1 ? (byte)0 : Bytes[j / 2]))
                return true;
        }
        return false;
    }

    private bool MatchesAt(ReadOnlySpan<byte> data, int start, int length,
        Func<int, bool> wildcardsByByte, Func<int, byte> byteAt)
    {
        for (var j = 0; j < length; j++)
        {
            if (wildcardsByByte(j)) continue;
            var actual = data[start + j];
            var expected = byteAt(j);
            // UTF-16LE de caracteres ASCII: los pares impares son cero y no
            // deben compararse con el carácter en mayúscula/minúscula.
            if (NoCase && actual is >= (byte)'A' and <= (byte)'Z') actual += 32;
            if (NoCase && expected is >= (byte)'A' and <= (byte)'Z') expected += 32;
            if (actual != expected) return false;
        }
        return true;
    }
}
