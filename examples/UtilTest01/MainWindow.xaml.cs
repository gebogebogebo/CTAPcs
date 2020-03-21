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
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace UtilTest01
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

        private byte[] credentialID;
        private string publicKey;

        private async void ButtonRegistration_Click(object sender, RoutedEventArgs e)
        {
            // server
            var rpid = "test.com";
            var challenge = g.FIDO2.Util.AttestationVerifier.CreateChallenge();

            // client
            var userName = "testUserName";
            var att = new g.FIDO2.Attestation();
            {
                var con = new g.FIDO2.CTAP.HID.HIDAuthenticatorConnector();

                var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid, challenge, new byte[1] { 0x01 });
                param.RpName = rpid;
                param.UserName = userName;
                param.UserDisplayName = "testUserDisplayName";
                param.Option_rk = false;
                param.Option_uv = false;

                string pin = "1234";

                var res = await con.MakeCredentialAsync(param, pin);
                if (res?.CTAPResponse?.Attestation != null) {
                    att = res.CTAPResponse.Attestation;
                }

            }

            // server
            if(att!=null) {
                var v = new g.FIDO2.Util.AttestationVerifier();
                var verify = v.Verify(rpid,challenge, att);
                if(verify.IsSuccess) {
                    this.credentialID = verify.CredentialID.ToArray();
                    this.publicKey = verify.PublicKeyPem;

                    // 公開鍵をX.509証明書に変換
                    var cert = v.CreateSelfSignedCertificate(verify,rpid, userName, new TimeSpan(365,0,0,0,0));

                    // Windowsの証明書ストアに保存
                    /*
                    // certmgr.msc
                    var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

                    store.Open(OpenFlags.ReadWrite);
                    store.Add(cert);
                    store.Close();
                    */

                    // ファイルに保存
                    var bcert = cert.Export(X509ContentType.Cert);
                    var fileName = @"c:\work\test.cer";
                    using (var writer = new BinaryWriter(new FileStream(fileName, FileMode.Create))) {
                        //書き込む処理
                        writer.Write(bcert);
                    }

                }
            }
        }

        private async void ButtonAuth_Click(object sender, RoutedEventArgs e)
        {
            // server
            var rpid = "test.com";
            var challenge = g.FIDO2.Util.Verifier.CreateChallenge();
            //var credentialId = g.FIDO2.Util.Common.HexStringToBytes("8F3045BE18CC2076E4EC8E5D9BCDEB7977B4217AE7B0503F0F5DBCF965CE172B28BFF3EE169E9F17D305E4D4C1FF0F7662A909D7ECA6AE63702AC9FFFBBAC229E907A29D29EE57E59949B075408A4C97780A04354407E73CAC72B31888E3DD09");

            // client
            var assertion = new g.FIDO2.Assertion();
            {
                var con = new g.FIDO2.CTAP.HID.HIDAuthenticatorConnector();

                var param = new g.FIDO2.CTAP.CTAPCommandGetAssertionParam(rpid,challenge, this.credentialID);
                param.Option_up = true;
                param.Option_uv = false;

                var res = await con.GetAssertionAsync(param, "1234");

                if (res?.CTAPResponse?.Assertion!=null) {
                    assertion = res.CTAPResponse.Assertion;
                }

                if (res?.CTAPResponse?.Assertion?.NumberOfCredentials > 0) {
                    for (int intIc = 0; intIc < res.CTAPResponse.Assertion.NumberOfCredentials - 1; intIc++) {
                        var next = await con.GetNextAssertionAsync();
                    }
                }

            }

            //server
            if(assertion != null) {
                var v = new g.FIDO2.Util.AssertionVerifier();
                var result = v.Verify(rpid,this.publicKey, challenge, assertion);
            }

        }

    }
}
