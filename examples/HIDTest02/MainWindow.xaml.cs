using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using g.FIDO2.CTAP.HID;
using g.FIDO2.Util;
using g.FIDO2;
using System.Collections.Generic;
using System.Text;

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
            GetFirstUSBDevice();
        }

        private void GetFirstUSBDevice()
        {
            List<string> fidoDevices = HIDAuthenticatorConnector.GetAllFIDODevicePaths();
            if (fidoDevices.Count == 0)
            { 
                //If there are no devices then we have no need for a connector
                con = null;
                return;
            }

            //If we already have a connector linked to this device then no further action is required
            if (fidoDevices.Contains(con?.GetDevicePath()))
                return;

            //Configure a new connector using the first returned device
            if(!(con is null))
                con.KeepAlive -= OnKeepAlive;

            con = new HIDAuthenticatorConnector(fidoDevices[0]);
            con.KeepAlive += OnKeepAlive;
        }

        private async void ButtonGetInfo_Click(object sender, RoutedEventArgs e)
        {
            GetFirstUSBDevice();
            StringBuilder message = new StringBuilder();
            var res = await con.GetInfoAsync();
            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Unauthorized) {
                message.Append("Excute Administrator ?");
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.NotConnected) {
                message.Append("FIDO Key Not Connected");
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok) {
                message.AppendLine($"GetInfoAsync");
                message.AppendLine($"- Status = {res.CTAPResponse.Status}");
                message.AppendLine($"- StatusMsg = {res.CTAPResponse.StatusMsg}");
                message.AppendLine($"-Json response:");
                message.AppendLine(res.CTAPResponse.ResponsePayloadJson);
            } else {
                message.Append("Error");
            }
            MessageBox.Show(message.ToString());
        }

        private void OnKeepAlive(object sender, EventArgs e)
        {
            // MakeCredentialAsync()、GetAssertionAsync()で
            // PIN認証が通ってFIDOキーのタッチ待ちになるとこのイベントが発生します
        }

        private async void ButtonMakeCredential_Click(object sender, RoutedEventArgs e)
        {
            GetFirstUSBDevice();
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
            GetFirstUSBDevice();
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
            GetFirstUSBDevice();
            var res = await con.ClientPINgetRetriesAsync();
            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok) {
                MessageBox.Show($"ClientPINgetRetriesAsync\r\n- Status = {res.CTAPResponse.Status}\r\n- StatusMsg = {res.CTAPResponse.StatusMsg}\r\n- PIN Retry Count = {res.CTAPResponse.RetryCount}");
            }
        }

        private async void ButtonWink_Click(object sender, RoutedEventArgs e)
        {
            GetFirstUSBDevice();
            for (int intIc = 0; intIc < 5; intIc++) {
                var ret = await con.WinkAsync();
                await Task.Delay(1000);
            }
        }

    }
}
