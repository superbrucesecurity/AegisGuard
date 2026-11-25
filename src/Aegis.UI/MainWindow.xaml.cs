using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using Aegis.Core;
using Microsoft.Web.WebView2.Core;

namespace Aegis.UI;

public partial class MainWindow : Window
{
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
            settings.AreHostObjectsAllowed = true;
            settings.IsWebMessageEnabled = false;

            // La SPA no recibe ninguna credencial. Las operaciones sensibles
            // pasan por este objeto nativo, que comprueba la elevación con UAC.
            Browser.CoreWebView2.AddHostObjectToScript("aegis", new AegisBridge());

            Browser.CoreWebView2.NavigationStarting += CoreWebView2_NavigationStarting;
            Browser.CoreWebView2.NavigationCompleted += CoreWebView2_NavigationCompleted;
            Browser.CoreWebView2.Navigate(AegisHttpEndpoints.DashboardUrl());
        }
        catch (Exception ex)
        {
            StatusText.Text = "No se pudo iniciar WebView2: " + ex.Message;
        }
    }

    private void CoreWebView2_NavigationStarting(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (!Uri.TryCreate(e.Uri, UriKind.Absolute, out var uri) ||
            !AegisHttpEndpoints.IsLocalDashboard(uri))
        {
            e.Cancel = true;
        }
    }

    private async void CoreWebView2_NavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (_retryCts.IsCancellationRequested) return;
        if (e.IsSuccess)
        {
            // NavigationCompleted solo indica que se cargó la página; el estado
            // real de protección lo muestra la SPA con los datos del servicio.
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
            Browser.CoreWebView2.Navigate(AegisHttpEndpoints.DashboardUrl());
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
