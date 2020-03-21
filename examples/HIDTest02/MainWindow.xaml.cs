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
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using g.FIDO2.CTAP.HID;
using g.FIDO2.Util;

namespace HIDTest02
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        HIDAuthenticatorConnector con;

        public MainWindow()
        {
            InitializeComponent();
            con = new HIDAuthenticatorConnector();
        }

        private async void ButtonGetInfo_Click(object sender, RoutedEventArgs e)
        {
            var res = await con.GetInfoAsync();
            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Unauthorized) {
                MessageBox.Show("Excute Administrator ?");
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.NotConnected) {
                MessageBox.Show("FIDO Key Not Connected");
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok) {
                MessageBox.Show($"GetInfoAsync\r\n- Status = {res.CTAPResponse.Status}\r\n- StatusMsg = {res.CTAPResponse.StatusMsg}"); ;
            } else {
                MessageBox.Show("Error");
            }
        }

        private void OnKeepAlive(object sender, EventArgs e)
        {
            // addLog($"- touch authenticator!");
        }

        private async void ButtonMakeCredential_Click(object sender, RoutedEventArgs e)
        {
            var rpid = "test.com";
            var challenge = AttestationVerifier.CreateChallenge();
            var userid = System.Text.Encoding.ASCII.GetBytes("12345");

            var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid, challenge, userid);

            var res = await con.MakeCredentialAsync(param, "1234");

            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.NotConnected) {
                //addLog("FIDO Key Not Connected");
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Timeout) {
                // addLog("UP or UV timeout");
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok) {
                if (res.CTAPResponse.Status == 0) {
                    if (res.CTAPResponse.Attestation != null) {
                        var v = new AttestationVerifier();
                        var verify = v.Verify(challenge, res.CTAPResponse.Attestation);

                        //var creid = g.FIDO2.Common.BytesToHexString(res.CTAPResponse.Attestation.CredentialId);
                        //addLog($"- CredentialID = {creid}\r\n");
                    }
                    MessageBox.Show($"MakeCredentialAsync\r\n- Status = {res.CTAPResponse.Status}\r\n- StatusMsg = {res.CTAPResponse.StatusMsg}");

                }
            }

        }
    }
}
