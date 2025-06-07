using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace BruteRatelGUI
{
    public partial class GeneratePayloadWindow : Window
    {
        public GeneratePayloadWindow()
        {
            InitializeComponent();
            LoadConfigData();
        }

        private void LoadConfigData()
        {
            List<PayloadConfig> configList = new List<PayloadConfig>
            {
                new PayloadConfig { Config = "Sleep", Value = "2" },
                new PayloadConfig { Config = "Indirect Syscall", Value = "✔" },
                new PayloadConfig { Config = "Sleep Technique", Value = "WaitForSingleObjectEx" },
            };

            ConfigDataGrid.ItemsSource = configList;
        }

        private void GenerateButton_Click(object sender, RoutedEventArgs e)
        {
            // Hardcoded source file path
            string sourceFilePath = @"C:\Users\ASUS\source\repos\ok\x64\Release\ok.exe";

            // Check if the file exists
            if (System.IO.File.Exists(sourceFilePath))
            {
                // Save File Dialog to choose the destination
                Microsoft.Win32.SaveFileDialog saveFileDialog = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "Executable Files (*.exe)|*.exe",
                    Title = "Save Payload As",
                    FileName = System.IO.Path.GetFileName(sourceFilePath)
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    string destinationFilePath = saveFileDialog.FileName;

                    // Copy the file to the chosen location
                    System.IO.File.Copy(sourceFilePath, destinationFilePath, true);
                    this.Close();
                    MessageBox.Show("Payload Generated and Saved!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);

                }
            }
            else
            {
                MessageBox.Show("Source file not found!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


    }

    public class PayloadConfig
    {
        public string Config { get; set; }
        public string Value { get; set; }
    }
}
