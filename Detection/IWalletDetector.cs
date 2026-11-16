using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace WalletScan.Detection;

/// <summary>
/// A detector contributes wallet hits for one class of artifact.
/// Implementations must be read-only and must not launch anything.
/// </summary>
public interface IWalletDetector
{
    /// <summary>Short name used in diagnostics.</summary>
    string Name { get; }

    /// <summary>Enumerate hits. Never throws for a single missing location.</summary>
    IEnumerable<Models.WalletHit> Detect(CancellationToken ct = default);
}

/// <summary>Well-known wallet signing identities, keyed by artifact name.</summary>
public static class WalletCatalog
{
    /// <summary>Extension ID => canonical wallet name. Chromium-family IDs.</summary>
    public static readonly IReadOnlyDictionary<string, string> Extensions =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["nkbihfbeogaeaoehlefnkodbefgpgknn"] = "MetaMask",
            ["acmacodkjbdgmoleebolmdjonilkdbch"] = "Rabby",
            ["bfnaelmomeimhlpmgjnjophhpkkoljpa"] = "Phantom",
            ["hnfanknocfeofbddgcijnmhnfnkdnaad"] = "Coinbase Wallet",
            ["dmkamcknogkgcdfhhbddcghachkejeap"] = "Keplr",
            ["fhbohimaelbohpjbbldcngcnapndodjp"] = "Binance Wallet",
            ["mcohilncbfahbmmocfclnghaaoodejpo"] = "OKX Wallet",
            ["egjidjbpglichdcondbcbdnbeeppgdph"] = "Trust Wallet",
            ["pdadjkfkgcafgbceimcpbkalnfnepbnk"] = "Exodus Web3",
            ["aholpfdialjgjfhomihkjbmgjidlcdno"] = "Exodus",
            ["jiidiaalihmmhddjgbnbgdfflelocpak"] = "Bitget Wallet",
            ["lgmpcpglpngdoalbgeoldeajfclnhafa"] = "SafePal",
            ["bhhhlbepdkbapadjdnnojkbgioiodbic"] = "Solflare",
            ["amkmjjmmflddogmhpjloimipbofnfjih"] = "Wombat",
            ["flpiciilemghbmfalicajoolhkkenfel"] = "Nami",
            ["lpnfaficcljmepnadbcebgcnacacmdia"] = "Leather",
            ["jbdaocneiiinmjbjlgalhcelgbejmnid"] = "Argent",
            ["dlcobpjiigpikoobohmabehhmhfoodbb"] = "Argent X",
            ["hpglfhgfnhbgpjdenjgmdgoeiappafln"] = "Taho",
            ["kkpllkodjeloidieedojogacfhpaihoh"] = "Enkrypt",
            ["bhghoamapcdpbohphigoooaddinpkbai"] = "XDEFI",
            ["jggheacbkmpikoklnphkgnmhoedclhcm"] = "Coin98",
            ["blnieiiffboillknjnepogjhkgnoapac"] = "Falcon",
        };

    /// <summary>
    /// Desktop wallet markers: process-free folder and registry names.
    /// Matched case-insensitively against install directories and uninstall keys.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> Desktop =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Exodus"] = "Exodus",
            ["Electrum"] = "Electrum",
            ["Ledger Live"] = "Ledger Live",
            ["Trezor Suite"] = "Trezor Suite",
            ["Atomic"] = "Atomic Wallet",
            ["AtomicWallet"] = "Atomic Wallet",
            ["Bitcoin Core"] = "Bitcoin Core",
            ["Monero GUI"] = "Monero GUI",
            ["Wasabi Wallet"] = "Wasabi Wallet",
            ["Sparrow"] = "Sparrow Wallet",
            ["BTCPay"] = "BTCPay Server",
            ["MetaMask"] = "MetaMask Desktop",
            ["Rabby"] = "Rabby Desktop",
            ["Coinomi"] = "Coinomi",
            ["Guarda"] = "Guarda",
            ["Zelcore"] = "Zelcore",
            ["Ravencoin"] = "Ravencoin Core",
            ["Litecoin Core"] = "Litecoin Core",
            ["Dogecoin Core"] = "Dogecoin Core",
        };
}
