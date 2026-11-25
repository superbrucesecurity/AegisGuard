using System.Configuration;
using System.Data;
using System.Windows;

namespace Aegis.UI;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        if (AegisBridge.TryHandleElevatedCall(e.Args, out var exitCode))
        {
            Shutdown(exitCode);
            return;
        }
        base.OnStartup(e);
    }
}
