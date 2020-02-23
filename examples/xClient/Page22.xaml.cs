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
    /// Page22.xaml の相互作用ロジック
    /// </summary>
    public partial class Page22 : Page
    {
        private static Page23 pageHIDPIN = null;
        private static Page24 pageHIDUV = null;
        private static Page25 pageBLEPIN = null;
        private static Page26 pageBLEUV = null;

        public Page22()
        {
            InitializeComponent();
        }

        private void ButtonHIDPIN_Click(object sender, RoutedEventArgs e)
        {
            if (pageHIDPIN == null) pageHIDPIN = new Page23();
            this.NavigationService.Navigate(pageHIDPIN);
        }

        private void ButtonHIDUV_Click(object sender, RoutedEventArgs e)
        {
            if (pageHIDUV == null) pageHIDUV = new Page24();
            this.NavigationService.Navigate(pageHIDUV);
        }

        private void ButtonBLEPIN_Click(object sender, RoutedEventArgs e)
        {
            if (pageBLEPIN == null) pageBLEPIN = new Page25();
            this.NavigationService.Navigate(pageBLEPIN);
        }

        private void ButtonBLEUV_Click(object sender, RoutedEventArgs e)
        {
            if (pageBLEUV == null) pageBLEUV = new Page26();
            this.NavigationService.Navigate(pageBLEUV);
        }
    }
}
