using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using g.FIDO2.CTAP.HID;

namespace xClient
{
    /// <summary>
    /// Page24.xaml の相互作用ロジック
    /// </summary>
    public partial class Page24 : Page
    {
        private static Page31 page = null;

        public Page24()
        {
            InitializeComponent();
        }

        private async void GetAssertion_Click(object sender, RoutedEventArgs e)
        {
            var app = (MainWindow)Application.Current.MainWindow;
            var ass = await app.Authenticate(app.GetFirstUSBConnector(), app.RPID, app.Challenge, app.CredentialID, null);
            if (ass == null) return;

            if (page == null) page = new Page31(ass);
            this.NavigationService.Navigate(page);

        }
    }
}
