using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using WalletScan.Models;

namespace WalletScan.Detection;

/// <summary>
/// Finds Firefox wallet extensions. Firefox does not use an ID-keyed extension directory
/// the way Chromium does: add-ons are single .xpi files in the profile's extensions folder,
/// named by their Mozilla GUID (email style like webextension@metamask.io, or a UUID in
/// braces). Detection is therefore filename matching against known GUIDs.
/// </summary>
public sealed class FirefoxExtensionDetector : IWalletDetector
{
    public string Name => "firefox-extensions";

    /// <summary>
    /// Verified against addons.mozilla.org GUIDs. Deliberately only includes IDs confirmed
    /// by exact AMO lookup, since a wrong GUID fails silently.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> Guids =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["webextension@metamask.io"] = "MetaMask",
            ["webextension-flask@metamask.io"] = "MetaMask Flask",
            ["{bad2476b-0830-455a-9519-e35caa33cfd5}"] = "Phantom",
            ["keplr-extension@keplr.app"] = "Keplr",
            ["{429b7095-8408-4d72-a8a2-37fcc4d67b77}"] = "Exodus",
            ["{21a9e8ea-7aa4-4aae-923c-ec8211f2779c}"] = "Enkrypt",
        };

    public IEnumerable<WalletHit> Detect(CancellationToken ct = default)
    {
        var profilesRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Mozilla", "Firefox", "Profiles");

        if (!Directory.Exists(profilesRoot)) yield break;

        IEnumerable<string> profiles;
        try { profiles = Directory.EnumerateDirectories(profilesRoot); }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException) { yield break; }

        foreach (var profileDir in profiles)
        {
            ct.ThrowIfCancellationRequested();
            var profile = Path.GetFileName(profileDir);

            // Firefox writes prefs.js on every run; a profile without it is a leftover.
            if (!File.Exists(Path.Combine(profileDir, "prefs.js"))) continue;

            var extDir = Path.Combine(profileDir, "extensions");
            if (!Directory.Exists(extDir)) continue;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(extDir, "*.xpi"); }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException) { continue; }

            foreach (var file in files)
            {
                var guid = Path.GetFileNameWithoutExtension(file);
                if (!Guids.TryGetValue(guid, out var wallet)) continue;

                DateTime? installed = null;
                try { installed = File.GetCreationTimeUtc(file); }
                catch (Exception e) when (e is UnauthorizedAccessException or IOException) { }

                yield return new WalletHit
                {
                    WalletName = wallet,
                    Kind = DetectionKind.BrowserExtension,
                    EvidencePath = extDir,
                    Browser = BrowserKind.Firefox,
                    Profile = profile,
                    InstalledUtc = installed,
                };
            }
        }
    }
}
