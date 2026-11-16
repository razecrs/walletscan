using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using WalletScan.Models;

namespace WalletScan.Detection;

/// <summary>
/// Finds wallet browser extensions by reading Chromium-family profile metadata.
/// Extension folders and Local Extension Settings are both keyed by extension ID,
/// so detection never needs to open the extension itself.
/// </summary>
public sealed class BrowserExtensionDetector : IWalletDetector
{
    public string Name => "browser-extensions";

    // Chromium-family user-data roots. Only existing roots are probed.
    private static readonly (BrowserKind Kind, string Root)[] Roots =
    {
        (BrowserKind.Chrome,  Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data")),
        (BrowserKind.Edge,    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data")),
        (BrowserKind.Brave,   Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"BraveSoftware\Brave-Browser\User Data")),
        (BrowserKind.Opera,   Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Opera Software\Opera Stable")),
        (BrowserKind.Vivaldi, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Vivaldi\User Data")),
        (BrowserKind.Chromium,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Chromium\User Data")),
    };

    private static readonly string[] SubTrees = { "Extensions", "Local Extension Settings", "Sync Extension Settings" };

    /// <summary>
    /// A user-data root can outlive the browser itself: uninstalling leaves the folders
    /// behind. Chromium writes Local State or Preferences on every real run, so requiring
    /// one keeps stale directories from being reported as an installed browser.
    /// </summary>
    private static bool LooksLive(string root)
    {
        try
        {
            return File.Exists(Path.Combine(root, "Local State"))
                || File.Exists(Path.Combine(root, "Preferences"))
                || Directory.Exists(Path.Combine(root, "Default", "Preferences"));
        }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException) { return false; }
    }

    /// <summary>
    /// Chrome writes Preferences into a profile on every run, so it is a useful signal of a
    /// used profile. It is not authoritative though: a profile can hold live extensions and
    /// still lack it. Profiles are therefore ranked, not filtered, and a hit from a profile
    /// with no Preferences is kept but labelled as such by the caller.
    /// </summary>
    private static bool IsLiveProfile(string profileDir)
    {
        try { return File.Exists(Path.Combine(profileDir, "Preferences")); }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException) { return false; }
    }

    public IEnumerable<WalletHit> Detect(CancellationToken ct = default)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (kind, root) in Roots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            if (!LooksLive(root)) continue;

            IEnumerable<string> profiles;
            try
            {
                profiles = Directory.EnumerateDirectories(root);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var profileDir in profiles)
            {
                var profile = Path.GetFileName(profileDir);
                // Skip Chromium's non-profile folders.
                if (profile is "Crashpad" or "ShaderCache" or "GrShaderCache" or "GraphiteDawnCache"
                    or "BrowserMetrics" or "SwReporter" or "component_crx_cache" or "extensions_crx_cache"
                    or "Safe Browsing" or "OptimizationHints" or "Segmentation Platform")
                    continue;

                foreach (var sub in SubTrees)
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (var hit in ProbeTree(kind, profile, Path.Combine(profileDir, sub), seen))
                        yield return hit;
                }
            }
        }
    }

    private static IEnumerable<WalletHit> ProbeTree(BrowserKind kind, string profile, string tree, HashSet<string> seen)
    {
        if (!Directory.Exists(tree)) yield break;

        IEnumerable<string> ids;
        try { ids = Directory.EnumerateDirectories(tree); }
        catch (UnauthorizedAccessException) { yield break; }
        catch (IOException) { yield break; }

        foreach (var dir in ids)
        {
            var id = Path.GetFileName(dir);
            if (!WalletCatalog.Extensions.TryGetValue(id, out var wallet)) continue;

            var key = $"{id}|{tree}";
            if (!seen.Add(key)) continue;

            DateTime? installed = null;
            string? version = null;
            try
            {
                installed = Directory.GetCreationTimeUtc(dir);
                // Chromium keeps versions as subfolders of the extension dir.
                var versionDir = Directory.EnumerateDirectories(dir).FirstOrDefault();
                if (versionDir is not null) version = Path.GetFileName(versionDir);
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            yield return new WalletHit
            {
                WalletName = wallet,
                Kind = DetectionKind.BrowserExtension,
                EvidencePath = tree,
                Browser = kind,
                Profile = profile,
                InstalledUtc = installed,
                Version = version,
            };
        }
    }
}
