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
using g.FIDO2.CTAP.HID;

namespace xClient
{
    /// <summary>
    /// Page5.xaml の相互作用ロジック
    /// </summary>
    public partial class Page5 : Page
    {
        private static Page11 page = null;

        public Page5()
        {
            InitializeComponent();
        }

        private async void MakeCredential_Click(object sender, RoutedEventArgs e)
        {
            var app = (MainWindow)Application.Current.MainWindow;
            var att = await app.Register(new HIDAuthenticatorConnector(), app.RPID, app.Challenge, null);
            if (att == null) return;

            if (page == null) page = new Page11(att);
            this.NavigationService.Navigate(page);
        }
    }
}
