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
using g.FIDO2.CTAP.HID;
using g.FIDO2.CTAP.BLE;

namespace xClient
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void addLog(string message)
        {
            Console.WriteLine($"{message}");
            // UIスレッドで実行するおまじない
            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(() => {
                textLog.Text += message + Environment.NewLine;
            }));
        }

        private void LogResponse(g.FIDO2.CTAP.DeviceStatus devSt, g.FIDO2.CTAP.CTAPResponse res)
        {
            addLog($"- DeviceStatus = {devSt.ToString()}");
            addLog($"- CTAP Status = 0x{res?.Status.ToString("X")}");
            addLog($"- CTAP StatusMsg = {res?.StatusMsg}");
            //addLog($"- CTAP SendPayloadJson = {res?.SendPayloadJson}");
            //addLog($"- CTAP ResponseDataJson = {res?.ResponsePayloadJson}");
            addLog("");
        }


        private async void ButtonInfoHID_Click(object sender, RoutedEventArgs e)
        {
            addLog("Info HID");
            var con = new HIDAuthenticatorConnector();
            var res = await con.GetInfoAsync();
            LogResponse(res.DeviceStatus, res.CTAPResponse);
        }

        private void ButtonRegisterHID_Click(object sender, RoutedEventArgs e)
        {
            addLog("Register HID");

            register(new HIDAuthenticatorConnector());

            /*
            // server
            var rpid = this.TextRPID.Text;
            var challenge = g.FIDO2.Common.HexStringToBytes(this.TextChallenge.Text);
            var pin = this.TextPIN.Text;

            // client
            g.FIDO2.Attestation att = null;
            {
                var con = new HIDAuthenticatorConnector();

                var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid, challenge);
                param.RpName = "test name";
                param.UserId = new byte[0];
                param.UserName = "testUserName";
                param.UserDisplayName = "testUserDisplayName";
                param.Option_rk = false;
                param.Option_uv = false;

                var res = await con.MakeCredentialAsync(param, pin);
                LogResponse(res.DeviceStatus, res.CTAPResponse);
                if (res?.CTAPResponse?.Status==0 && res?.CTAPResponse?.Attestation != null) {
                    att = res.CTAPResponse.Attestation;
                }

            }

            if (att != null) {
                var att_b = g.FIDO2.Serializer.Serialize(att);

                addLog("Attestation ---");
                addLog(g.FIDO2.Common.BytesToHexString(att_b));
                addLog("--- Attestation");

            }
            */

        }

        private void ButtonLoginHID_Click(object sender, RoutedEventArgs e)
        {

        }


        BLEAuthenticatorScanner scannerBLE;
        ulong addressBLE = 0;
        BLEAuthenticatorConnector conBLE;

        private void ButtonRegisterBLE_Click(object sender, RoutedEventArgs e)
        {
            scannerBLE = new BLEAuthenticatorScanner();
            scannerBLE.FindDevice += OnFindDevice;
            scannerBLE.Start();
            addLog("Scan Start . Please turn on BLE FIDO key");

        }

        private async void OnFindDevice(object sender, g.FIDO2.CTAP.BLE.BLEAuthenticatorScanner.FindDeviceEventArgs e)
        {

            addLog($"<OnFindDevice>");
            scannerBLE.Stop();

            addLog($"- BluetoothAddress = {e.BluetoothAddress}");
            addLog($"- CompanyId = 0x{e.CompanyId.ToString("X")}");
            addLog($"- ManufacturerData = 0x{g.FIDO2.Common.BytesToHexString(e.ManufacturerData)}");
            addressBLE = e.BluetoothAddress;

            var ret = await this.connectBLE();
            if( ret == false) {
                return;
            }
            register(conBLE);
        }

        private async Task<bool> connectBLE()
        {
            conBLE = new BLEAuthenticatorConnector();

            conBLE.PacketSizeByte = 155;       // AllinPass
            //con.ConnectedDevice += OnConnectedDevice;
            //con.DisconnectedDevice += OnDisconnectedDevice;
            var result = await conBLE.ConnectAsync(this.addressBLE);
            if (result == false) {
                addLog("Connect Error BLE FIDO key");
                return false;
            }
            addLog("Connected BLE FIDO key");
            return true;
        }

        private void register(g.FIDO2.CTAP.AuthenticatorConnector con)
        {
            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(async() => {

                // server
                var rpid = this.TextRPID.Text;
                var challenge = g.FIDO2.Common.HexStringToBytes(this.TextChallenge.Text);
                var pin = this.TextPIN.Text;

                var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid, challenge);
                param.RpName = "test name";
                param.UserId = new byte[0];
                param.UserName = "testUserName";
                param.UserDisplayName = "testUserDisplayName";
                param.Option_rk = false;
                param.Option_uv = false;

                g.FIDO2.Attestation att = null;
                {
                    addLog("up FIDO key");

                    var res = await con.MakeCredentialAsync(param, pin);
                    LogResponse(res.DeviceStatus, res.CTAPResponse);
                    if (res?.CTAPResponse?.Status == 0 && res?.CTAPResponse?.Attestation != null) {
                        att = res.CTAPResponse.Attestation;
                    }
                }
                if (att != null) {
                    var att_b = g.FIDO2.Serializer.Serialize(att);

                    addLog("Attestation ---");
                    addLog(g.FIDO2.Common.BytesToHexString(att_b));
                    addLog("--- Attestation");

                }

                if(con is BLEAuthenticatorConnector) {
                    conBLE.Disconnect();
                }

            }));
        }

    }
}
