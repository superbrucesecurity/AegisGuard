using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using Aegis.Core;
using Microsoft.Web.WebView2.Core;

namespace Aegis.UI;

public partial class MainWindow : Window
{
    private const string DashboardUrl = "http://127.0.0.1:8787/";
    private readonly CancellationTokenSource _retryCts = new();
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
                // El token solo se expone al origen local; una navegación externa
                // accidental no debe recibir la credencial del servicio.
                var script = $"if (location.origin === 'http://127.0.0.1:8787') " +
                             $"window.AEGIS_TOKEN = {JsonSerializer.Serialize(token)};";
                await Browser.CoreWebView2.AddScriptToExecuteOnDocumentCreatedAsync(script).ConfigureAwait(true);
            }
            else
            {
                StatusText.Text = "No se pudo leer la credencial local del servicio.";
            }

            Browser.CoreWebView2.NavigationStarting += CoreWebView2_NavigationStarting;
            Browser.CoreWebView2.NavigationCompleted += CoreWebView2_NavigationCompleted;
            Browser.CoreWebView2.Navigate(DashboardUrl);
        }
        catch (Exception ex)
        {
            StatusText.Text = "No se pudo iniciar WebView2: " + ex.Message;
        }
    }

    private void CoreWebView2_NavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (!Uri.TryCreate(e.Uri, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttp ||
            !string.Equals(uri.Host, "127.0.0.1", StringComparison.Ordinal) ||
            uri.Port != 8787)
        {
            e.Cancel = true;
        }
    }

    private async void CoreWebView2_NavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (_retryCts.IsCancellationRequested) return;
        if (e.IsSuccess)
        {
            // NavigationCompleted solo indica que se cargó la página; la API
            // puede estar devolviendo 401. El estado real lo muestra la SPA.
            StatusText.Text = "Interfaz cargada · compruebe el estado de la API";
            return;
        }
        if (_retryCount++ >= 20)
        {
            StatusText.Text = "El servicio Aegis Guard no responde. Compruebe que esté ejecutándose.";
            return;
        }
        StatusText.Text = "Esperando al servicio local...";
        try
        {
            await Task.Delay(1500, _retryCts.Token).ConfigureAwait(true);
        }
        catch (TaskCanceledException)
        {
            return;
        }
        if (!_retryCts.IsCancellationRequested && Browser.CoreWebView2 is not null)
            Browser.CoreWebView2.Navigate(DashboardUrl);
    }

    private static string ReadToken()
    {
        var path = Path.Combine(AegisPaths.DataRoot, "ui-token");
        try
        {
            return File.Exists(path) ? File.ReadAllText(path).Trim() : string.Empty;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
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
        _retryCts.Cancel();
        if (Browser.CoreWebView2 is not null)
        {
            Browser.CoreWebView2.NavigationStarting -= CoreWebView2_NavigationStarting;
            Browser.CoreWebView2.NavigationCompleted -= CoreWebView2_NavigationCompleted;
        }
        Browser.Dispose();
        _retryCts.Dispose();
    }
}
