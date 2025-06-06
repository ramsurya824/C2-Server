using System.Windows;
using YourNamespace;

namespace BruteRatelGUI
{
    public partial class AddDNSListenerWindow : Window
    {
        public string ListenerName { get;  set; }
        public string Host { get;  set; }
        public int Port { get;  set; }
        public AddDNSListenerWindow()
        {
            InitializeComponent();
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void OK_Click(object sender, RoutedEventArgs e)
        {
            // Retrieve user input and validate
            ListenerName = ListenerNameTextBox.Text;
            Host = HostTextBox.Text;
            int port = int.Parse(PortTextBox.Text);
            Listener newListener = new Listener
            {
                Name = ListenerName,
                Host = Host,
                Port = port,
                Type = "DNS",
            };
            MainWindow mainWindow = Application.Current.MainWindow as MainWindow;
            mainWindow.Listeners.Add(newListener);
            mainWindow.UpdateListenersVisibility();
            this.Close();
        }

        
    }
}
