using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using WalletScan.Detection;
using WalletScan.Models;

namespace WalletScan;

public partial class MainWindow : Window
{
    private readonly ScanEngine _engine = new();
    private CancellationTokenSource? _cts;
    private IReadOnlyList<WalletHit> _lastResults = Array.Empty<WalletHit>();

    public MainWindow()
    {
        InitializeComponent();
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        if (_cts is not null) return;

        _cts = new CancellationTokenSource();
        SetBusy(true);
        StatusText.Text = "Scanning…";
        EmptyText.Visibility = Visibility.Collapsed;

        try
        {
            var results = await _engine.ScanAsync(_cts.Token);
            _lastResults = results;
            ResultsList.ItemsSource = results;

            StatusText.Text = results.Count == 0
                ? "Scan complete. No wallet software found."
                : $"Found {results.Count} item(s).";
            EmptyText.Visibility = results.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            ExportButton.IsEnabled = results.Count > 0;
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Scan cancelled.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Scan failed: {ex.GetType().Name}";
            EmptyText.Visibility = Visibility.Visible;
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            SetBusy(false);
        }
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastResults.Count == 0) return;

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            FileName = $"walletscan-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
            Filter = "CSV|*.csv",
            DefaultExt = ".csv",
        };
        if (dialog.ShowDialog(this) != true) return;

        var sb = new StringBuilder();
        sb.AppendLine("wallet,type,where,installed_utc,version,evidence");
        foreach (var hit in _lastResults)
        {
            sb.AppendLine(string.Join(",",
                Csv(hit.WalletName), Csv(hit.Kind.ToString()), Csv(hit.Location),
                Csv(hit.InstalledText), Csv(hit.Version ?? ""), Csv(hit.EvidencePath)));
        }

        try
        {
            File.WriteAllText(dialog.FileName, sb.ToString(), Encoding.UTF8);
            StatusText.Text = $"Exported {_lastResults.Count} row(s).";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Export failed: {ex.GetType().Name}";
        }
    }

    private void SetBusy(bool busy)
    {
        ScanButton.IsEnabled = !busy;
        CancelButton.IsEnabled = busy;
    }

    private static string Csv(string value)
    {
        if (value.Contains('"') || value.Contains(',') || value.Contains('\n'))
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        return value;
    }
}
