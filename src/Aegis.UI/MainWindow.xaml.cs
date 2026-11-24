using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using Microsoft.Web.WebView2.Core;

namespace Aegis.UI;

public partial class MainWindow : Window
{
    private const string DashboardUrl = "http://127.0.0.1:8787/";
    private int _retryCount;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var userData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AegisGuard", "WebView2");
            Directory.CreateDirectory(userData);
            var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: userData).ConfigureAwait(true);
            await Browser.EnsureCoreWebView2Async(environment).ConfigureAwait(true);

            var settings = Browser.CoreWebView2.Settings;
            settings.AreDefaultContextMenusEnabled = false;
            settings.AreDevToolsEnabled = false;
            settings.IsPasswordAutosaveEnabled = false;
            settings.IsGeneralAutofillEnabled = false;
            settings.IsZoomControlEnabled = false;
            settings.AreHostObjectsAllowed = false;
            settings.IsWebMessageEnabled = false;

            var token = ReadToken();
            if (!string.IsNullOrEmpty(token))
            {
                await Browser.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(
                    $"window.AEGIS_TOKEN = {JsonSerializer.Serialize(token)};").ConfigureAwait(true);
            }
            else
            {
                StatusText.Text = "No se pudo leer la credencial local del servicio.";
            }

            Browser.CoreWebView2.NavigationCompleted += CoreWebView2_NavigationCompleted;
            Browser.CoreWebView2.Navigate(DashboardUrl);
        }
        catch (Exception ex)
        {
            StatusText.Text = "No se pudo iniciar WebView2: " + ex.Message;
        }
    }

    private async void CoreWebView2_NavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (e.IsSuccess)
        {
            StatusText.Text = "Conectado · motor local activo";
            return;
        }
        if (_retryCount++ >= 20)
        {
            StatusText.Text = "El servicio Aegis Guard no responde. Compruebe que esté ejecutándose.";
            return;
        }
        StatusText.Text = "Esperando al servicio local...";
        await Task.Delay(1500).ConfigureAwait(true);
        if (Browser.CoreWebView2 is not null) Browser.CoreWebView2.Navigate(DashboardUrl);
    }

    private static string ReadToken()
    {
        var root = Environment.GetEnvironmentVariable("PROGRAMDATA") ?? @"C:\ProgramData";
        var path = Path.Combine(root, "AegisGuard", "ui-token");
        return File.Exists(path) ? File.ReadAllText(path).Trim() : string.Empty;
    }

    private void TitleBar_Drag(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left) DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        Browser.Dispose();
    }
}
