using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Windows;
using System.Windows.Input;
using System.Threading.Tasks;

namespace FatalityLoader
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
                this.DragMove();
        }

        private void ExitButton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private async void LoadButton_Click(object sender, RoutedEventArgs e)
        {
            string? currentDir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule?.FileName);
            if (currentDir == null) currentDir = AppDomain.CurrentDomain.BaseDirectory;

            string[] possibleNames = { "FatalityLoader.dll", "TestDLL_x64.dll", "TestDLL.dll" };
            string dllPath = "";

            foreach (var name in possibleNames)
            {
                string path = Path.Combine(currentDir, name);
                if (File.Exists(path))
                {
                    dllPath = path;
                    break;
                }
            }

            try
            {
                if (string.IsNullOrEmpty(dllPath))
                {
                    StatusText.Text = "DLL Not Found!";
                    StatusText.Foreground = System.Windows.Media.Brushes.Red;
                    StatusText.ToolTip = $"Looked in: {currentDir}\nPut FatalityLoader.dll there.";
                    return;
                }
                StatusText.Text = "Reading DLL...";
                StatusText.Foreground = System.Windows.Media.Brushes.Yellow;

                byte[] dllBytes = await File.ReadAllBytesAsync(dllPath);

                if (!IsAdministrator())
                {
                    StatusText.Text = "Run as Admin!";
                    StatusText.Foreground = System.Windows.Media.Brushes.Red;
                    return;
                }

                StatusText.Text = "Injecting...";
                StatusText.Foreground = System.Windows.Media.Brushes.Yellow;
                await Task.Delay(500);

                string? error = Injector.Inject("cs2", dllBytes);
                
                if (error == null)
                {
                    StatusText.Text = "Injected!";
                    StatusText.Foreground = System.Windows.Media.Brushes.LimeGreen;
                    StatusText.ToolTip = "Success! Check the game.";
                }
                else
                {
                    StatusText.Text = "Failed";
                    StatusText.Foreground = System.Windows.Media.Brushes.Red;
                    StatusText.ToolTip = error;
                    
                    if (error.Length < 15) StatusText.Text = error;
                    else if (error.Contains("Process not found")) StatusText.Text = "Waiting for CS2...";
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "Error: " + ex.Message;
                StatusText.Foreground = System.Windows.Media.Brushes.Red;
                StatusText.ToolTip = ex.Message;
            }
        }
        private bool IsAdministrator()
        {
            using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
            {
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
        }
    }
}
