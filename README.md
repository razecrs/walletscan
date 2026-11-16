# WalletScan

Local inventory of crypto wallet software installed on a Windows PC.

Finds browser wallet extensions and desktop wallet applications, and reports only
non-sensitive metadata: wallet name, installation status, install date, browser and
browser profile.

The app never launches wallet software and never reads seed phrases, private keys or
balances.

## Why it works without opening anything

Both artifact classes leave file system and registry traces that key on identity:

- Chromium family browsers store extensions under
  `User Data\<profile>\Extensions\<extension-id>` and `...\Local Extension Settings\<extension-id>`.
  Wallet extensions are recognised by their published extension ID.
- Desktop wallets leave uninstall registry entries and per-user install directories.

Because detection is driven by those keys, no wallet has to be started and no vault file
has to be parsed.

## Design

- `IWalletDetector` is the extension point. One implementation per artifact class.
- `ScanEngine` runs detectors, isolates failures so one bad detector cannot abort a scan,
  and de-duplicates the merged result.
- Detectors are read-only and require no administrator rights.
- WPF is presentation only and holds no detection logic.

Current detectors: `BrowserExtensionDetector`, `DesktopAppDetector`.

## Build and run

```
dotnet build -c Release
dotnet run -c Release
```

Requires the .NET SDK with the Windows Desktop workload.

## Status

Prototype. Detection, UI, CSV export, cancellation and graceful degradation on access
denied paths are working. Next steps are unit tests over the detector layer against a
fixture profile tree, and a signed single file build.
