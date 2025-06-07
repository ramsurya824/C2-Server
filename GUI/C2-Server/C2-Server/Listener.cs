using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace YourNamespace
{
    

    public class Listener : INotifyPropertyChanged
    {
        private bool _isRunning;
        private Brush _rowColor;

        public string Name { get; set; }
        public string Host { get; set; }
        public int Port { get; set; }
        public string Type { get; set; }

        public bool IsRunning
        {
            get => _isRunning;
            set
            {
                _isRunning = value;
                OnPropertyChanged();
                RowColor = _isRunning ? Brushes.Green : Brushes.White;
            }
        }

        public Brush RowColor
        {
            get => _rowColor;
            set
            {
                _rowColor = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

}
