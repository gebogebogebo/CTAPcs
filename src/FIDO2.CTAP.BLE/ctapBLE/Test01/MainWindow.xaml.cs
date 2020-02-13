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
            addLog($"- CTAP SendPayloadJson = {res?.SendPayloadJson}");
            addLog($"- CTAP ResponseDataJson = {res?.ResponsePayloadJson}");
            addLog("");
        }

        private void OnFindDevice(object sender, g.FIDO2.CTAP.BLE.BLEAuthenticatorScanner.FindDeviceEventArgs e)
        {

            addLog($"<OnFindDevice>");
            scanner.Stop();

            addLog($"- BluetoothAddress = {e.BluetoothAddress}");
            addLog($"- CompanyId = 0x{e.CompanyId.ToString("X")}");
            addLog($"- ManufacturerData = 0x{g.FIDO2.Common.BytesToHexString(e.ManufacturerData)}");

            bleAddress = e.BluetoothAddress;

            ButtonConnect_Click(null, null);
        }

        private void OnConnectedDevice(object sender, EventArgs e)
        {
            addLog($"<OnConnectedDevice>");
        }

        private void OnDisconnectedDevice(object sender, EventArgs e)
        {
            addLog($"<OnDisconnectedDevice>");
        }

        public MainWindow()
        {
            InitializeComponent();
        }

        private void ButtonStartScan_Click(object sender, RoutedEventArgs e)
        {
            scanner = new BLEAuthenticatorScanner();
            scanner.FindDevice += OnFindDevice;
            if (scanner.Start()) {
                addLog("Scan Start.BLE FIDOキーをONにしてください");
                addLog("");
            } else {
                addLog("Scan Start Error");
                addLog("");
            }
        }

        private void ButtonStopScan_Click(object sender, RoutedEventArgs e)
        {
            addLog("<Scan Stop>");
            scanner.Stop();
        }

        private async void ButtonConnect_Click(object sender, RoutedEventArgs e)
        {
            addLog("<Connect>");

            con = new BLEAuthenticatorConnector();
            con.PacketSizeByte = 155;       // AllinPass
            con.ConnectedDevice += OnConnectedDevice;
            con.DisconnectedDevice += OnDisconnectedDevice;
            var result = await con.ConnectAsync(this.bleAddress);
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

            var param = new g.FIDO2.CTAP.CTAPCommandGetAssertionParam();
            param.RpId = "BLEtest.com";

            param.ClientDataHash = Common.CreateClientDataHash("this is challenge");

            //param.AllowList_CredentialId = Common.HexStringToBytes("D2A464B2FDFB219245ED5C1E81FCEC8452915B3DB13BE0D608691F51909A2136331CE8663803E23A6B7B895F38B98B70A8165578391C571B45EF15EEF7282D36617CAA36931CBE6DF69A8166F18EB1ED0634B3D0055C186C794AF355464FE8A6");
            param.AllowList_CredentialId = Common.HexStringToBytes("1A9862CFD3AF8FA152622D3612B3AAE5ACD59FC3EB65A3F71390EBFA56E79C64CAB890AF184E341EBB616D0E9220BA25800F1A16974E08258744FA2C7B6EABD8F467E285A3CA20899E41C67111880CF455AAEE68DC0D9DCEF87FEED076635BEB");
            param.Option_up = true;
            param.Option_uv = false;

            //var res = await con.GetAssertion(param);
            var res = await con.GetAssertionAsync(param, "1234");
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

            var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam();
            param.RpId = "BLEtest.com";
            param.RpName = "BLEtest name";
            param.UserId = new byte[0];
            param.UserName = "testUserName";
            param.UserDisplayName = "testUserDisplayName";
            param.Option_rk = false;
            param.Option_uv = false;
            param.ClientDataHash = g.FIDO2.CTAP.BLE.Common.CreateClientDataHash("this is challenge");

            string pin = "1234";

            var res = await con.MakeCredentialAsync(param, pin);
            LogResponse(res.DeviceStatus, res.CTAPResponse);

            if (res?.CTAPResponse?.Attestation != null) {
                var creid = g.FIDO2.Common.BytesToHexString(res.CTAPResponse.Attestation.CredentialId);
                addLog($"- CredentialID = {creid}");
            }

        }
    }
}
