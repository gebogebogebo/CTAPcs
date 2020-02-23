using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace xClient
{
    /// <summary>
    /// Page3.xaml の相互作用ロジック
    /// </summary>
    public partial class Page3 : Page
    {
        private static Page4 pageHIDPIN = null;
        private static Page5 pageHIDUV = null;
        private static Page6 pageBLEPIN = null;
        private static Page7 pageBLEUV = null;

        public Page3()
        {
            InitializeComponent();
        }

        private void ButtonHIDPIN_Click(object sender, RoutedEventArgs e)
        {
            if (pageHIDPIN == null) pageHIDPIN = new Page4();
            this.NavigationService.Navigate(pageHIDPIN);
        }

        private void ButtonHIDUV_Click(object sender, RoutedEventArgs e)
        {
            if (pageHIDUV == null) pageHIDUV = new Page5();
            this.NavigationService.Navigate(pageHIDUV);
        }

        private void ButtonBLEPIN_Click(object sender, RoutedEventArgs e)
        {
            if (pageBLEPIN == null) pageBLEPIN = new Page6();
            this.NavigationService.Navigate(pageBLEPIN);
        }

        private void ButtonBLEUV_Click(object sender, RoutedEventArgs e)
        {
            if (pageBLEUV == null) pageBLEUV = new Page7();
            this.NavigationService.Navigate(pageBLEUV);
        }
    }
}
