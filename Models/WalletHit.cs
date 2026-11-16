using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace WalletScan.Models;

/// <summary>How a wallet artifact was found.</summary>
public enum DetectionKind
{
    BrowserExtension,
    DesktopApplication,
}

/// <summary>Which browser a browser-extension hit came from.</summary>
public enum BrowserKind
{
    Chrome,
    Edge,
    Brave,
    Firefox,
    Opera,
    Vivaldi,
    Chromium,
}

/// <summary>
/// One detected wallet installation. Deliberately contains only non-sensitive
/// metadata: nothing is read from inside the wallet's own storage.
/// </summary>
public sealed record WalletHit
{
    public required string WalletName { get; init; }
    public required DetectionKind Kind { get; init; }
    public required string EvidencePath { get; init; }
    public BrowserKind? Browser { get; init; }
    public string? Profile { get; init; }
    public DateTime? InstalledUtc { get; init; }
    public string? Version { get; init; }

    /// <summary>Human-readable location summary, e.g. "Chrome · Profile 2".</summary>
    public string Location => Browser is null
        ? "Desktop application"
        : $"{Browser} · {Profile ?? "default"}";

    public string InstalledText => InstalledUtc?.ToString("yyyy-MM-dd HH:mm") ?? "unknown";
}
