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

namespace HIDTest01
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        private void addLog(string message)
        {
            Console.WriteLine($"{message}");
            // UIスレッドで実行するおまじない
            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(() => {
                textLog.Text += message + Environment.NewLine;
            }));
        }

        private void LogResponse(g.FIDO2.CTAP.CTAPResponse res)
        {
            addLog($"- Status = 0x{res.Status.ToString("X")}");
            addLog($"- StatusMsg = {res.StatusMsg}");
            addLog($"- SendPayloadJson = {res.SendPayloadJson}");
            addLog($"- ResponseDataJson = {res.ResponsePayloadJson}");
            addLog("");
        }

        private void LogResponse(g.FIDO2.CTAP.DeviceStatus devSt,g.FIDO2.CTAP.CTAPResponse res)
        {
            addLog($"- DeviceStatus = {devSt.ToString()}");
            addLog($"- CTAP Status = 0x{res.Status.ToString("X")}");
            addLog($"- CTAP StatusMsg = {res.StatusMsg}");
            addLog($"- CTAP SendPayloadJson = {res.SendPayloadJson}");
            addLog($"- CTAP ResponseDataJson = {res.ResponsePayloadJson}");
            addLog("");
        }

        HIDAuthenticatorConnector con;

        public MainWindow()
        {
            InitializeComponent();
            con = new HIDAuthenticatorConnector();
        }

        private async void ButtonGetInfo_Click(object sender, RoutedEventArgs e)
        {
            addLog("<GetInfo>");
            var res = await con.GetInfoAsync();
            LogResponse(res.DeviceStatus,res.CTAPResponse);
        }

        private async void ButtonClientPINgetRetries_Click(object sender, RoutedEventArgs e)
        {
            {
                addLog("<ClientPIN getRetries>");
                var res = await con.ClientPINgetRetriesAsync();
                LogResponse(res.CTAPResponse);

                if (res?.CTAPResponse != null) {
                    addLog($"- RetryCount = {res.CTAPResponse.RetryCount}\r\n");
                }
            }

            {
                addLog("<ClientPIN getPINToken>");
                var res2 = await con.ClientPINgetPINTokenAsync("1234");
                LogResponse(res2);
            }
        }

        private async void ButtonGetAssertion_Click(object sender, RoutedEventArgs e)
        {
            addLog("<getAssertion>");

            var param = new g.FIDO2.CTAP.CTAPCommandGetAssertionParam();
            param.RpId = "test.com";

            param.ClientDataHash = Common.CreateClientDataHash("this is challenge");

            param.AllowList_CredentialId = Common.HexStringToBytes("8F3045BE18CC2076E4EC8E5D9BCDEB7977B4217AE7B0503F0F5DBCF965CE172B28BFF3EE169E9F17D305E4D4C1FF0F7662A909D7ECA6AE63702AC9FFFBBAC229E907A29D29EE57E59949B075408A4C97780A04354407E73CAC72B31888E3DD09");
            param.Option_up = true;
            param.Option_uv = false;

            var res = await con.GetAssertionAsync(param, "1234");
            LogResponse(res);

            if (res?.Assertion?.NumberOfCredentials > 0) {
                for (int intIc = 0; intIc < res.Assertion.NumberOfCredentials - 1; intIc++) {
                    var next = await con.GetNextAssertionAsync();
                    LogResponse(next);
                }
            }

        }

        private async void ButtonMakeCredential_Click(object sender, RoutedEventArgs e)
        {
            addLog("<makeCredential>");

            var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam();
            param.RpId = "test.com";
            param.RpName = "test name";
            param.UserId = new byte[0];
            param.UserName = "testUserName";
            param.UserDisplayName = "testUserDisplayName";
            param.Option_rk = false;
            param.Option_uv = false;
            param.ClientDataHash = Common.CreateClientDataHash("this is challenge");

            string pin = "1234";

            var res = await con.MakeCredentialAsync(param, pin);
            LogResponse(res);

            if (res?.Attestation != null) {
                var creid = g.FIDO2.Common.BytesToHexString(res.Attestation.CredentialId);
                addLog($"- CredentialID = {creid}\r\n");
            }

        }

        private async void ButtonClientPINchangePIN_Click(object sender, RoutedEventArgs e)
        {
            var res = await con.ClientPINchangePINAsync("1234","9999");
            LogResponse(res);
        }

        private async void ButtonClientPINsetPIN_Click(object sender, RoutedEventArgs e)
        {
            var res = await con.ClientPINsetPINAsync("1234");
            LogResponse(res.DeviceStatus,res.CTAPResponse);
        }

        private void ButtonIsConnected_Click(object sender, RoutedEventArgs e)
        {
            addLog("<IsConnected>");
            var res = con.IsConnected();
            addLog($"- Connected = {res}\r\n");
        }
    }
}
