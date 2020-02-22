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
        private static Page23 page = null;

        public Page22()
        {
            InitializeComponent();
        }

        private void ButtonHIDPIN_Click(object sender, RoutedEventArgs e)
        {
            if (page == null) page = new Page23();
            this.NavigationService.Navigate(page);
        }
    }
}
