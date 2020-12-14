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
using g.FIDO2;
using g.FIDO2.CTAP.BLE;
using g.FIDO2.Util;

namespace Test01
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック | Interaction logic
    /// </summary>
    public partial class MainWindow : Window
    {
        BLEAuthenticatorScanner scanner;
        ulong bleAddress = 0;
        BLEAuthenticatorConnector con;

        private string pubkey;

        private void addLog(string message)
        {
            string log = DateTime.Now.ToString() + " " + message;
            Console.WriteLine($"{log}");

            // UIスレッドで実行するおまじない | Magic to run in UI thread
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
                addLog($"- ManufacturerData = 0x{e.ManufacturerData.ToHexString()}");

                bleAddress = e.BluetoothAddress;

                // そのままコネクトすることをやめる | Stop connecting as it is
                //ButtonConnect_Click(null, null);
                addLog($"Scan OK ! : Next Click [Connect]Button");

                //Auto Connecting
                //DoConnect().GetAwaiter().GetResult();

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
            addLog($"<OnKeepAlive>");
            addLog($"- touch authenticator!");
        }

        private async Task DoConnect()
        {
            try
            {
                addLog($"<Connect> BLE Address = {this.bleAddress.ToString("X")}");

                if (this.bleAddress == 0)
                {
                    addLog($"- Connect Error BLE Address");
                    return;
                }

                con = new BLEAuthenticatorConnector();
                //con.PacketSizeByte = 155;       // AllinPass
                con.ConnectedDevice += OnConnectedDevice;
                con.DisconnectedDevice += OnDisconnectedDevice;
                con.KeepAlive += OnKeepAlive;
                var result = await con.ConnectAsync(this.bleAddress);
                if (result == false)
                {
                    addLog("- Connect Error");
                }
                addLog($"Connect OK");
            }
            catch (Exception ex)
            {
                addLog($"- Connect Error Exception: {ex.Message}");
            }
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
                    addLog("Scan Start.BLE FIDOキーをONにしてください | Please turn on the FIDO key");
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
            await DoConnect();
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

                if (res?.CTAPResponse != null)
                {
                    addLog($"- RetryCount = {res.CTAPResponse.RetryCount}\r\n");
                }
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
            byte[] creid = null;

            //Get the credential id entered in the text box (or stored from make credential)
            if (!string.IsNullOrEmpty(textBoxCreID.Text))
            {
                creid = g.FIDO2.Common.HexStringToBytes(textBoxCreID.Text);
            }
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

            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok)
            {
                if (res.CTAPResponse.Assertion != null)
                {
                    // verify
                    var v = new AssertionVerifier();
                    var verify = v.Verify(rpid, pubkey, challenge, res.CTAPResponse.Assertion);
                    addLog($"- Verify = {verify.IsSuccess}");
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

            if (res?.CTAPResponse.Status == 0)
            {
                if (res.CTAPResponse?.Attestation != null)
                {
                    //Verify
                    var v = new AttestationVerifier();
                    var verify = v.Verify(rpid, challenge, res.CTAPResponse.Attestation);
                    addLog($"- Verify = {verify.IsSuccess}\r\n- - PublicKey = {verify.PublicKeyPem}");

                    var creid = res.CTAPResponse.Attestation.CredentialId.ToHexString();
                    addLog($"- CredentialID = {creid}");
                    textBoxCreID.Text = creid;
                    pubkey = verify.PublicKeyPem;
                }
            }

        }

        private void ButtonClear_Click(object sender, RoutedEventArgs e)
        {
            textLog.Text = "";
        }

        private async void ButtonClientPINchangePIN_Click(object sender, RoutedEventArgs e)
        {
            var res = await con.ClientPINchangePINAsync("9999", "1234");
            LogResponse(res.DeviceStatus, res.CTAPResponse);
        }

        private async void ButtonClientPINsetPIN_Click(object sender, RoutedEventArgs e)
        {
            var res = await con.ClientPINsetPINAsync("1234");
            LogResponse(res.DeviceStatus, res.CTAPResponse);
        }
    }
}
