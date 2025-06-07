using System.Diagnostics;
using System;
using System.Collections.ObjectModel;
using System.Windows;
using YourNamespace;
using System.Windows.Input;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Net.Sockets;
using System.Text;
using System.Runtime.InteropServices.ComTypes;
using System.Net;
namespace BruteRatelGUI
{
    
    public partial class MainWindow : Window
    {
        public ObservableCollection<Listener> Listeners { get; set; }  
        public MainWindow()
        {
            InitializeComponent();
            Listeners = new ObservableCollection<Listener>();
            ListenersDataGrid.ItemsSource = Listeners;
            //CommandLine.Text = "Command Line Interface Ready...\n> "; // Initial Message
            //CommandLine.CaretIndex = CommandLine.Text.Length; // Move cursor to end
            UpdateListenersVisibility();
        }

        private void AddListener(string name, string host, int port, string type)
        {
            Listeners.Add(new Listener { Name = name, Host = host, Port = port, Type=type});
            UpdateListenersVisibility();
        }

        // Remove all listeners (Example)
        private void ClearListeners()
        {
            Listeners.Clear();
            UpdateListenersVisibility();
        }

        public void UpdateListenersVisibility()
        {
            if (Listeners.Count == 0)
            {
                NoListenersTextBlock.Visibility = Visibility.Visible;
                ListenersDataGrid.Visibility = Visibility.Collapsed;
            }
            else
            {
                NoListenersTextBlock.Visibility = Visibility.Collapsed;
                ListenersDataGrid.Visibility = Visibility.Visible;
            }
        }
    

    
    

    // Event Handlers for Menu Items
    private void AddDNSListener_Click(object sender, RoutedEventArgs e)
        {
            
            //AddListener("DNS Listener", "127.0.0.1", 53, "DNS");
            AddDNSListenerWindow addDNSListener = new AddDNSListenerWindow();
            addDNSListener.ShowDialog();
        }

        private void AddDohListener_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Add DOH Listener selected.", "C4 Profiler");
        }

        private void AddHttpListener_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Hosted Files selected.", "C4 Profiler");
        }

        private void AddHttpsListener_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Change Root Page selected.", "C4 Profiler");
        }

        private void Autoruns_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Autoruns selected.", "C4 Profiler");
        }

        private void PayloadProfiler_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("Payload Profiler selected.", "C4 Profiler");
        }

        private void PsExecConfig_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("PsExec Config selected.", "C4 Profiler");
        }

        private void ClickScripts_Click(object sender, RoutedEventArgs e)
        {
            MessageBox.Show("ClickScripts selected.", "C4 Profiler");
        }

        private void EditListener_Click(object sender, RoutedEventArgs e)
        {
            if (ListenersDataGrid.SelectedItem is Listener selectedListener)
            {
                // Open a window to edit the listener
                AddDNSListenerWindow editWindow = new AddDNSListenerWindow
                {
                    ListenerName = selectedListener.Name,
                    Host = selectedListener.Host,
                    Port = selectedListener.Port
                };

                if (editWindow.ShowDialog() == true)
                {
                    // Update the selected listener's properties
                    selectedListener.Name = editWindow.ListenerName;
                    selectedListener.Host = editWindow.Host;
                    selectedListener.Port = editWindow.Port;

                    // Refresh the DataGrid
                    ListenersDataGrid.Items.Refresh();
                }
            }
        }

        private void GeneratePayload_Click(object sender, RoutedEventArgs e)
        {
            if (ListenersDataGrid.SelectedItem is Listener selectedListener)
            {
                GeneratePayloadWindow payloadWindow = new GeneratePayloadWindow();
                payloadWindow.ShowDialog();

            //    string exeFilePath = @"C:\Users\ASUS\Documents\payload.exe";

            //    if (!File.Exists(exeFilePath))
            //    {
            //        MessageBox.Show("Payload file not found!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            //        return;
            //    }

            //    // Read the EXE file into memory
            //    byte[] exeBytes = File.ReadAllBytes(exeFilePath);

            //    // Prompt user to save the EXE file
            //    SaveFileDialog saveFileDialog = new SaveFileDialog
            //    {
            //        Filter = "Executable Files (*.exe)|*.exe",
            //        FileName = $"{selectedListener.Name}_payload.exe"
            //    };

            //    if (saveFileDialog.ShowDialog() == true)
            //    {
            //        File.WriteAllBytes(saveFileDialog.FileName, exeBytes);
            //        MessageBox.Show("Payload saved successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            //    }
            }
        }

        private void DeleteListener_Click(object sender, RoutedEventArgs e)
        {
            if (ListenersDataGrid.SelectedItem is Listener selectedListener)
            {
                if (MessageBox.Show($"Are you sure you want to delete {selectedListener.Name}?", "Confirm Delete", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                {
                    Listeners.Remove(selectedListener);
                    UpdateListenersVisibility();
                }
            }
        }

        // Add a field to store the running process
        private Process runningProcess = null;

        private void StartStopListener_Click(object sender, RoutedEventArgs e)
        {
            if (ListenersDataGrid.SelectedItem is Listener selectedListener)
            {
                selectedListener.IsRunning = !selectedListener.IsRunning;
                string state = selectedListener.IsRunning ? "Started" : "Stopped";
                
                // Check if the listener is already running
                if (runningProcess != null && !runningProcess.HasExited)
                {
                    // Stop the running process
                    try
                    {
                        runningProcess.Kill(); // Terminate the process
                        runningProcess.Dispose();
                        runningProcess = null;
                        selectedListener.IsRunning = false;
                        EventLogs.AppendText($"[Info]: {selectedListener.Name} has been stopped.\n");
                        EventLogs.ScrollToEnd();
                    }
                    catch (Exception ex)
                    {
                        EventLogs.AppendText($"[Error]: Failed to stop {selectedListener.Name}. {ex.Message}\n");
                        EventLogs.ScrollToEnd();
                    }
                    return; // Exit the method as we have stopped the process
                }

                // Start the process
                try
                {
                    selectedListener.IsRunning = true;
                    string pythonPath = "python"; // Path to Python executable
                    string scriptPath = @"C:\Users\ASUS\Documents\dns-server.py";
                    string arguments = $"{scriptPath} --port 53 --udp";

                    // Process configuration
                    ProcessStartInfo start = new ProcessStartInfo
                    {
                        FileName = pythonPath,
                        Arguments = arguments,
                        UseShellExecute = false, // Do not use OS shell
                        RedirectStandardOutput = true, // Capture script output
                        RedirectStandardError = true, // Capture errors
                        CreateNoWindow = true // Run without creating a new window
                    };

                    runningProcess = new Process { StartInfo = start };
                    runningProcess.Start();

                    // Read output asynchronously
                    _ = Task.Run(() =>
                    {
                        try
                        {
                            using (StreamReader outputReader = runningProcess.StandardOutput)
                            using (StreamReader errorReader = runningProcess.StandardError)
                            {
                                string output;
                                while ((output = outputReader.ReadLine()) != null)
                                {
                                    Dispatcher.Invoke(() =>
                                    {
                                        EventLogs.AppendText($"[Output]: {output}\n");
                                        EventLogs.ScrollToEnd();
                                    });
                                }

                                string error;
                                while ((error = errorReader.ReadLine()) != null)
                                {
                                    Dispatcher.Invoke(() =>
                                    {
                                        EventLogs.AppendText($"[Error]: {error}\n");
                                        EventLogs.ScrollToEnd();
                                    });
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Dispatcher.Invoke(() =>
                            {
                                EventLogs.AppendText($"[Error]: An error occurred while reading script output. {ex.Message}\n");
                                EventLogs.ScrollToEnd();
                            });
                        }
                    });

                    EventLogs.AppendText($"[Info]: {selectedListener.Name} has been started.\n");
                    EventLogs.ScrollToEnd();
                }
                catch (Exception ex)
                {
                    EventLogs.AppendText($"[Error]: Failed to start {selectedListener.Name}. {ex.Message}\n");
                    EventLogs.ScrollToEnd();
                    selectedListener.IsRunning = false;
                }

                ListenersDataGrid.Items.Refresh();
            }
        }


        private void CommandInputTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            // Check if Enter is pressed
            if (e.Key == Key.Enter)
            {
                string command = CommandInputTextBox.Text.Trim(); // Get the entered command
                CommandInputTextBox.Clear(); // Clear the input box

                // Process the command and get the result
                ProcessCommand(command);

                // Append the command and result to the output box
                CommandOutputTextBox.AppendText($"\n$> {command}\n");
                CommandOutputTextBox.ScrollToEnd(); // Scroll to the latest output
            }
        }

        // Command Processing Logic
        private void ProcessCommand(string command)
        {

            if (command=="clear"){
                CommandOutputTextBox.Clear();
                // Clear output box

            }

            using (TcpClient client = new TcpClient("127.0.0.1", 9000))
            using (NetworkStream stream = client.GetStream())
            {
                byte[] data = Encoding.UTF8.GetBytes(command);
                stream.Write(data, 0, data.Length);

            }

            Task.Run(() =>
            {
                TcpListener listener = new TcpListener(IPAddress.Parse("127.0.0.1"), 9001);
                listener.Start();
                try
                {
                    using (TcpClient responseClient = listener.AcceptTcpClient())
                    using (NetworkStream responseStream = responseClient.GetStream())
                    {
                        byte[] buffer = new byte[1024];
                        int bytesRead = responseStream.Read(buffer, 0, buffer.Length);
                        string response = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                        Dispatcher.Invoke(() =>
                        {
                            CommandOutputTextBox.AppendText($"\nResponse: {response}");
                        });
                    }
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() =>
                    {
                        CommandOutputTextBox.AppendText($"\nError receiving response: {ex.Message}");
                    });
                }
                finally
                {
                    listener.Stop();
                }
            });
        }
    }


}



