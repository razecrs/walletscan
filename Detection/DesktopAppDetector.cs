using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Win32;
using WalletScan.Models;

namespace WalletScan.Detection;

/// <summary>
/// Finds installed desktop wallet applications via uninstall registry keys and
/// per-user install directories. Registry and folder metadata only.
/// </summary>
public sealed class DesktopAppDetector : IWalletDetector
{
    public string Name => "desktop-apps";

    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string UninstallKey32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    public IEnumerable<WalletHit> Detect(CancellationToken ct = default)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var hit in FromRegistry(RegistryHive.CurrentUser, RegistryView.Default, UninstallKey, seen, ct)) yield return hit;
        foreach (var hit in FromRegistry(RegistryHive.LocalMachine, RegistryView.Registry64, UninstallKey, seen, ct)) yield return hit;
        foreach (var hit in FromRegistry(RegistryHive.LocalMachine, RegistryView.Registry32, UninstallKey32, seen, ct)) yield return hit;
        foreach (var hit in FromFolders(seen, ct)) yield return hit;
    }

    private static IEnumerable<WalletHit> FromRegistry(RegistryHive hive, RegistryView view, string path,
        HashSet<string> seen, CancellationToken ct)
    {
        RegistryKey? root = null;
        try { root = RegistryKey.OpenBaseKey(hive, view).OpenSubKey(path); }
        catch (Exception e) when (e is UnauthorizedAccessException or IOException or System.Security.SecurityException) { }

        if (root is null) yield break;

        using (root)
        {
            string[] names;
            try { names = root.GetSubKeyNames(); }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException) { yield break; }

            foreach (var subName in names)
            {
                ct.ThrowIfCancellationRequested();
                RegistryKey? sub = null;
                try { sub = root.OpenSubKey(subName); }
                catch (Exception e) when (e is UnauthorizedAccessException or IOException) { }
                if (sub is null) continue;

                using (sub)
                {
                    var display = sub.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(display)) continue;

                    var wallet = MatchWallet(display);
                    if (wallet is null) continue;
                    if (!seen.Add(wallet)) continue;

                    var install = sub.GetValue("InstallLocation") as string;
                    DateTime? installed = null;
                    try
                    {
                        var stamp = sub.GetValue("InstallDate") as string;
                        if (stamp is not null && DateTime.TryParseExact(stamp, "yyyyMMdd",
                                null, System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed))
                            installed = parsed;
                        else if (install is not null && Directory.Exists(install))
                            installed = Directory.GetCreationTimeUtc(install);
                    }
                    catch (Exception e) when (e is UnauthorizedAccessException or IOException) { }

                    yield return new WalletHit
                    {
                        WalletName = wallet,
                        Kind = DetectionKind.DesktopApplication,
                        EvidencePath = $"registry: {hive}\\{path}\\{subName}",
                        InstalledUtc = installed,
                        Version = sub.GetValue("DisplayVersion") as string,
                    };
                }
            }
        }
    }

    private static IEnumerable<WalletHit> FromFolders(HashSet<string> seen, CancellationToken ct)
    {
        var scopes = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        foreach (var scope in scopes)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(scope)) continue;

            string[] dirs;
            try { dirs = Directory.GetDirectories(scope); }
            catch (Exception e) when (e is UnauthorizedAccessException or IOException) { continue; }

            foreach (var dir in dirs)
            {
                var wallet = MatchWallet(Path.GetFileName(dir));
                if (wallet is null) continue;
                if (!seen.Add(wallet)) continue;

                DateTime? installed = null;
                try { installed = Directory.GetCreationTimeUtc(dir); }
                catch (Exception e) when (e is UnauthorizedAccessException or IOException) { }

                yield return new WalletHit
                {
                    WalletName = wallet,
                    Kind = DetectionKind.DesktopApplication,
                    EvidencePath = dir,
                    InstalledUtc = installed,
                };
            }
        }
    }

    private static string? MatchWallet(string candidate)
    {
        // Exact-ish match first, then contains, so "Exodus 24.1.1" still resolves.
        if (WalletCatalog.Desktop.TryGetValue(candidate.Trim(), out var exact)) return exact;
        foreach (var (needle, wallet) in WalletCatalog.Desktop)
            if (candidate.Contains(needle, StringComparison.OrdinalIgnoreCase))
                return wallet;
        return null;
    }
}
