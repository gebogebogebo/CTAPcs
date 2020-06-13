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

namespace Test01
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        BLEAuthenticatorScanner scanner;
        ulong bleAddress = 0;
        BLEAuthenticatorConnector con;

        private void addLog(string message)
        {
            string log = DateTime.Now.ToString() + " " + message;
            Console.WriteLine($"{log}");
            // UIスレッドで実行するおまじない
            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(() => {
                textLog.Text += log + Environment.NewLine;
            }));
        }

        private void LogResponse(g.FIDO2.CTAP.DeviceStatus devSt, g.FIDO2.CTAP.CTAPResponse res)
        {
            addLog($"- DeviceStatus = {devSt.ToString()}");
            addLog($"- CTAP Status = 0x{res?.Status.ToString("X")}");
            addLog($"- CTAP StatusMsg = {res?.StatusMsg}");
            addLog($"- CTAP SendPayloadJson = {res?.SendPayloadJson}");
            addLog($"- CTAP ResponseDataJson = {res?.ResponsePayloadJson}");
            addLog("");
        }

        private void OnFindDevice(object sender, g.FIDO2.CTAP.BLE.BLEAuthenticatorScanner.FindDeviceEventArgs e)
        {
            try {
                addLog($"<OnFindDevice>");
                scanner.Stop();

                addLog($"- BluetoothAddress = {e.BluetoothAddress.ToString("X")}");
                addLog($"- CompanyId = 0x{e.CompanyId.ToString("X")}");
                addLog($"- ManufacturerData = 0x{g.FIDO2.Common.BytesToHexString(e.ManufacturerData)}");

                bleAddress = e.BluetoothAddress;

                // そのままコネクトすることをやめる
                //ButtonConnect_Click(null, null);
                addLog($"Scan OK ! : Next Click [Connect]Button");

            } catch (Exception ex) {
                addLog($"- OnFindDevice Error Exception{ex.Message}");
            }
        }

        private void OnConnectedDevice(object sender, EventArgs e)
        {
            addLog($"<OnConnectedDevice>");
        }

        private void OnDisconnectedDevice(object sender, EventArgs e)
        {
            addLog($"<OnDisconnectedDevice>");
        }

        private void OnKeepAlive(object sender, EventArgs e)
        {
            addLog($"<OnKeppAlive>");
            addLog($"- touch authenticator!");
        }

        public MainWindow()
        {
            InitializeComponent();
        }

        private void ButtonStartScan_Click(object sender, RoutedEventArgs e)
        {
            try {
                scanner = new BLEAuthenticatorScanner();
                scanner.FindDevice += OnFindDevice;
                if (scanner.Start()) {
                    addLog("Scan Start.BLE FIDOキーをONにしてください");
                    addLog("");
                } else {
                    addLog("Scan Start Error");
                    addLog("");
                }
            } catch (Exception ex) {
                addLog($"- Scan Start Error Exception{ex.Message}");
            }
        }

        private void ButtonStopScan_Click(object sender, RoutedEventArgs e)
        {
            addLog("<Scan Stop>");
            scanner.Stop();
        }

        private async void ButtonConnect_Click(object sender, RoutedEventArgs e)
        {
            try {
                addLog($"<Connect> BLE Address = {this.bleAddress.ToString("X")}");

                if( this.bleAddress == 0) {
                    addLog($"- Connect Error BLE Address");
                    return;
                }

                con = new BLEAuthenticatorConnector();
                //con.PacketSizeByte = 155;       // AllinPass
                con.ConnectedDevice += OnConnectedDevice;
                con.DisconnectedDevice += OnDisconnectedDevice;
                con.KeepAlive += OnKeepAlive;
                var result = await con.ConnectAsync(this.bleAddress);
                if (result == false) {
                    addLog("- Connect Error");
                }
                addLog($"Connect OK");
            } catch (Exception ex) {
                addLog($"- Connect Error Exception{ex.Message}");
            }
        }

        private void ButtonDiscon_Click(object sender, RoutedEventArgs e)
        {
            addLog("<Disconnect>");
            con.Disconnect();
        }

        private async void ButtonGetInfo_Click(object sender, RoutedEventArgs e)
        {
            addLog("<GetInfo>");
            var res = await con.GetInfoAsync();
            LogResponse(res.DeviceStatus, res.CTAPResponse);
        }

        private async void ButtonClientPINgetRetries_Click(object sender, RoutedEventArgs e)
        {
            {
                addLog("<ClientPIN getRetries>");
                var res = await con.ClientPINgetRetriesAsync();
                LogResponse(res.DeviceStatus, res.CTAPResponse);
            }

            {
                addLog("<ClientPIN getPINToken>");
                var res = await con.ClientPINgetPINTokenAsync("1234");
                LogResponse(res.DeviceStatus, res.CTAPResponse);
            }
        }

        private async void ButtonGetAssertion_Click(object sender, RoutedEventArgs e)
        {
            addLog("<getAssertion>");

            var rpid = "BLEtest.com";
            var challenge = Encoding.ASCII.GetBytes("this is challenge");
            var creid = g.FIDO2.Common.HexStringToBytes("158134A7F56968833FD7FE85A8408E9DACD59FC3EB65A3F71390EBFA56E79C64AB7C841236D58FF6A5B1A03B31923923FA624332C61C51044F9738F0D5A9E6CDC3598236CA95D17D123B461B96CE38F68912E3F55B7D49A09ABCF40BA487B99B");

            var param = new g.FIDO2.CTAP.CTAPCommandGetAssertionParam(rpid,challenge,creid);

            param.Option_up = false;
            param.Option_uv = true;

            //var res = await con.GetAssertion(param);
            var res = await con.GetAssertionAsync(param, "");
            LogResponse(res.DeviceStatus, res.CTAPResponse);

            if (res?.CTAPResponse?.Assertion?.NumberOfCredentials > 0) {
                for (int intIc = 0; intIc < res.CTAPResponse.Assertion.NumberOfCredentials - 1; intIc++) {
                    var next = await con.GetNextAssertionAsync();
                    LogResponse(next.DeviceStatus,next.CTAPResponse);
                }
            }
        }

        private async void ButtonMakeCredential_Click(object sender, RoutedEventArgs e)
        {
            addLog("<makeCredential>");

            var rpid = "BLEtest.com";
            var challenge = Encoding.ASCII.GetBytes("this is challenge");

            var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid,challenge, new byte[0]);
            param.RpName = "BLEtest name";
            param.UserName = "testUserName";
            param.UserDisplayName = "testUserDisplayName";
            param.Option_rk = false;
            param.Option_uv = true;

            string pin = "";

            var res = await con.MakeCredentialAsync(param, pin);
            LogResponse(res.DeviceStatus, res.CTAPResponse);

            if (res?.CTAPResponse?.Attestation != null) {
                var creid = g.FIDO2.Common.BytesToHexString(res.CTAPResponse.Attestation.CredentialId);
                addLog($"- CredentialID = {creid}");
            }

        }
    }
}
