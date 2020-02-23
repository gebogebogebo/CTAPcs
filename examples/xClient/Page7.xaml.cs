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
using System.Windows.Threading;
using g.FIDO2.CTAP.BLE;

namespace xClient
{
    /// <summary>
    /// Page7.xaml の相互作用ロジック
    /// </summary>
    public partial class Page7 : Page
    {
        private static Page11 page = null;

        private BLEAuthenticatorScanner scannerBLE;
        private ulong addressBLE = 0;
        private BLEAuthenticatorConnector conBLE;

        public Page7()
        {
            InitializeComponent();
        }

        private void MakeCredential_Click(object sender, RoutedEventArgs e)
        {
            scannerBLE = new BLEAuthenticatorScanner();
            scannerBLE.FindDevice += OnFindDevice;
            scannerBLE.Start();
        }

        private async void OnFindDevice(object sender, g.FIDO2.CTAP.BLE.BLEAuthenticatorScanner.FindDeviceEventArgs e)
        {
            scannerBLE.Stop();
            addressBLE = e.BluetoothAddress;

            var ret = await this.connectBLE();
            if (ret == false) {
                return;
            }

            // UIスレッドで実行するおまじない
            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(async () => {
                var app = (MainWindow)Application.Current.MainWindow;
                var att = await app.Register(conBLE, app.RPID, app.Challenge, null);
                if (att == null) return;

                if (page == null) page = new Page11(att);
                this.NavigationService.Navigate(page);

            }));
        }

        private async Task<bool> connectBLE()
        {
            conBLE = new BLEAuthenticatorConnector();

            conBLE.PacketSizeByte = 155;       // AllinPass
            //con.ConnectedDevice += OnConnectedDevice;
            //con.DisconnectedDevice += OnDisconnectedDevice;
            var result = await conBLE.ConnectAsync(this.addressBLE);
            if (result == false) {
                return false;
            }
            return true;
        }

    }
}
