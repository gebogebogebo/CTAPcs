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
using g.FIDO2.CTAP.NFC;

namespace NFCTest01
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

        private void LogResponse(g.FIDO2.CTAP.DeviceStatus devSt, g.FIDO2.CTAP.CTAPResponse res)
        {
            addLog($"- DeviceStatus = {devSt.ToString()}");
            addLog($"- CTAP Status = 0x{res?.Status.ToString("X")}");
            addLog($"- CTAP StatusMsg = {res?.StatusMsg}");
            addLog($"- CTAP SendPayloadJson = {res?.SendPayloadJson}");
            addLog($"- CTAP ResponseDataJson = {res?.ResponsePayloadJson}");
            addLog("");
        }

        NFCAuthenticatorConnector con;

        public MainWindow()
        {
            InitializeComponent();
            con = new NFCAuthenticatorConnector();
        }

        private async void ButtonGetInfo_Click(object sender, RoutedEventArgs e)
        {
            addLog("<GetInfo>");
            var res = await con.GetInfoAsync();
            LogResponse(res.DeviceStatus, res.CTAPResponse);
        }

        private void ButtonIsConnected_Click(object sender, RoutedEventArgs e)
        {
            addLog("<IsConnected>");
            var res = con.IsConnected();
            addLog($"- Connected = {res}\r\n");
        }

        private async void ButtonClientPINgetRetries_Click(object sender, RoutedEventArgs e)
        {
            {
                addLog("<ClientPIN getRetries>");
                var res = await con.ClientPINgetRetriesAsync();
                LogResponse(res.DeviceStatus, res.CTAPResponse);

                if (res?.CTAPResponse != null) {
                    addLog($"- RetryCount = {res.CTAPResponse.RetryCount}\r\n");
                }
            }

            {
                addLog("<ClientPIN getPINToken>");
                var res2 = await con.ClientPINgetPINTokenAsync("1234");
                LogResponse(res2.DeviceStatus, res2.CTAPResponse);
            }
        }

        private async void ButtonGetAssertion_Click(object sender, RoutedEventArgs e)
        {
            addLog("<getAssertion>");

            var rpid = "test.com";
            var challenge = Encoding.ASCII.GetBytes("this is challenge");
            var creid = g.FIDO2.Common.HexStringToBytes("4096E0A8CC913B60041C03C3979442599C55B63675D6B1924CA493A6538EBC67940B234ABF1AED171ABDCD442774A1AE369DFFDCF81160B4C150F685DE8C9AFE");

            var param = new g.FIDO2.CTAP.CTAPCommandGetAssertionParam(rpid,challenge,creid);

            param.Option_up = true;
            param.Option_uv = false;

            var res = await con.GetAssertionAsync(param, "1234");
            LogResponse(res.DeviceStatus, res.CTAPResponse);

            if (res?.CTAPResponse?.Assertion?.NumberOfCredentials > 0) {
                for (int intIc = 0; intIc < res.CTAPResponse.Assertion.NumberOfCredentials - 1; intIc++) {
                    var next = await con.GetNextAssertionAsync();
                    LogResponse(res.DeviceStatus, next.CTAPResponse);
                }
            }

        }

        private async void ButtonMakeCredential_Click(object sender, RoutedEventArgs e)
        {
            addLog("<makeCredential>");

            var rpid = "test.com";
            var challenge = Encoding.ASCII.GetBytes("this is challenge");

            var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid, challenge);
            param.RpName = "test name";
            param.UserId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            param.UserName = "testUserName";
            param.UserDisplayName = "testUserDisplayName";
            param.Option_rk = false;
            param.Option_uv = false;

            string pin = "1234";

            var res = await con.MakeCredentialAsync(param, pin);
            LogResponse(res.DeviceStatus, res.CTAPResponse);

            if (res?.CTAPResponse?.Attestation?.CredentialId != null) {
                var creid = g.FIDO2.Common.BytesToHexString(res.CTAPResponse.Attestation.CredentialId);
                addLog($"- CredentialID = {creid}\r\n");
            }
        }

        private async void ButtonClientPINchangePIN_Click(object sender, RoutedEventArgs e)
        {
            var res = await con.ClientPINchangePINAsync("1234", "9999");
            LogResponse(res.DeviceStatus, res.CTAPResponse);
        }

        private async void ButtonClientPINsetPIN_Click(object sender, RoutedEventArgs e)
        {
            var res = await con.ClientPINsetPINAsync("1234");
            LogResponse(res.DeviceStatus, res.CTAPResponse);

        }
    }
}
