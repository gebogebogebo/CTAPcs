using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using g.FIDO2.CTAP.HID;
using g.FIDO2.Util;
using g.FIDO2;

namespace HIDTest02
{
    public partial class MainWindow : Window
    {
        private HIDAuthenticatorConnector con;
        private byte[] creid;
        private string pubkey;

        public MainWindow()
        {
            InitializeComponent();
            con = new HIDAuthenticatorConnector();
            con.KeepAlive += OnKeepAlive;
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
            // MakeCredentialAsync()、GetAssertionAsync()で
            // PIN認証が通ってFIDOキーのタッチ待ちになるとこのイベントが発生します
        }

        private async void ButtonMakeCredential_Click(object sender, RoutedEventArgs e)
        {
            string rpid = "test.com";
            var challenge = AttestationVerifier.CreateChallenge();
            var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid, challenge);
            var res = await con.MakeCredentialAsync(param, "1234");
            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.NotConnected) {
                // FIDOキーが接続されていない場合
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Timeout) {
                // FIDOキーのタッチ待ちでTimeoutした場合
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok) {
                string verifyResult = "";
                if (res.CTAPResponse.Status == 0) {
                    if (res.CTAPResponse.Attestation != null) {
                        // verify
                        var v = new AttestationVerifier();
                        var verify = v.Verify(rpid,challenge, res.CTAPResponse.Attestation);
                        verifyResult = $"- Verify = {verify.IsSuccess}\r\n- CredentialID = {Common.BytesToHexString(verify.CredentialID)}\r\n- PublicKey = {verify.PublicKeyPem}";
                        if (verify.IsSuccess) {
                            // store
                            creid = verify.CredentialID.ToArray();
                            pubkey = verify.PublicKeyPem;
                        }
                    }
                }
                MessageBox.Show($"MakeCredentialAsync\r\n- Status = {res.CTAPResponse.Status}\r\n- StatusMsg = {res.CTAPResponse.StatusMsg}\r\n{verifyResult}");
            }

        }

        private async void ButtonGetAssertion_Click(object sender, RoutedEventArgs e)
        {
            var rpid = "test.com";
            var challenge = AttestationVerifier.CreateChallenge();
            var param = new g.FIDO2.CTAP.CTAPCommandGetAssertionParam(rpid, challenge, creid);
            param.Option_up = true;

            var res = await con.GetAssertionAsync(param, "1234");
            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.NotConnected) {
                // FIDOキーが接続されていない場合
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Timeout) {
                // FIDOキーのタッチ待ちでTimeoutした場合
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok) {
                string verifyResult = "";
                if ( res.CTAPResponse.Assertion != null) {
                    // verify
                    var v = new AssertionVerifier();
                    var verify = v.Verify(rpid,pubkey,challenge, res.CTAPResponse.Assertion);
                    verifyResult = $"- Verify = {verify.IsSuccess}";
                }
                MessageBox.Show($"GetAssertionAsync\r\n- Status = {res.CTAPResponse.Status}\r\n- StatusMsg = {res.CTAPResponse.StatusMsg}\r\n{verifyResult}");
            }
        }

        private async void ButtonClientPINgetRetries_Click(object sender, RoutedEventArgs e)
        {
            var con2 = new HIDAuthenticatorConnector();
            var res = await con2.ClientPINgetRetriesAsync();
            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok) {
                MessageBox.Show($"ClientPINgetRetriesAsync\r\n- Status = {res.CTAPResponse.Status}\r\n- StatusMsg = {res.CTAPResponse.StatusMsg}\r\n- PIN Retry Count = {res.CTAPResponse.RetryCount}");
            }
        }

        private async void ButtonWink_Click(object sender, RoutedEventArgs e)
        {
            var con2 = new HIDAuthenticatorConnector();
            for (int intIc = 0; intIc < 5; intIc++) {
                var ret = await con2.WinkAsync();
                await Task.Delay(1000);
            }
        }

    }
}
