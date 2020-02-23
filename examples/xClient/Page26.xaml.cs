using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using g.FIDO2.CTAP.BLE;

namespace xClient
{
    /// <summary>
    /// Page26.xaml の相互作用ロジック
    /// </summary>
    public partial class Page26 : Page
    {
        private static Page31 page = null;

        private BLEAuthenticatorScanner scannerBLE;
        private ulong addressBLE = 0;
        private BLEAuthenticatorConnector conBLE;

        public Page26()
        {
            InitializeComponent();
        }

        private void GetAssertion_Click(object sender, RoutedEventArgs e)
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
                var ass = await app.Authenticate(conBLE, app.RPID, app.Challenge, app.CredentialID, null);
                if (ass == null) return;

                if (page == null) page = new Page31(ass);
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
