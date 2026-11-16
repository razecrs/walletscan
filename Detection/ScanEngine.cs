using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using WalletScan.Models;

namespace WalletScan.Detection;

/// <summary>Runs every registered detector and de-duplicates the combined result.</summary>
public sealed class ScanEngine
{
    private readonly IReadOnlyList<IWalletDetector> _detectors;

    public ScanEngine(IEnumerable<IWalletDetector>? detectors = null)
    {
        _detectors = (detectors ?? new IWalletDetector[]
        {
            new BrowserExtensionDetector(),
            new FirefoxExtensionDetector(),
            new DesktopAppDetector(),
        }).ToList();
    }

    public async Task<IReadOnlyList<WalletHit>> ScanAsync(CancellationToken ct = default)
    {
        var all = new List<WalletHit>();

        foreach (var detector in _detectors)
        {
            var hits = await Task.Run(() =>
            {
                var bag = new List<WalletHit>();
                try { bag.AddRange(detector.Detect(ct)); }
                catch (OperationCanceledException) { throw; }
                catch (Exception) { /* one bad detector must not kill the scan */ }
                return bag;
            }, ct);
            all.AddRange(hits);
        }

        // Collapse duplicates: same wallet from the same browser/profile counts once,
        // preferring the richest record (the one that found an install date).
        return all
            .GroupBy(h => (h.WalletName, h.Kind, h.Browser, h.Profile))
            .Select(g => g.OrderByDescending(h => h.InstalledUtc.HasValue).First())
            .OrderBy(h => h.WalletName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(h => h.Browser)
            .ToList();
    }
}
