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

namespace xClient
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : NavigationWindow
    {
        public string RPID;
        public byte[] Challenge;
        public byte[] CredentialID;

        public MainWindow()
        {
            InitializeComponent();
        }

        public async Task<g.FIDO2.Attestation> Register(g.FIDO2.CTAP.AuthenticatorConnector con, string rpid, byte[] challenge, string pin)
        {
            return await Task<g.FIDO2.Attestation>.Run(async () => {
                var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid, challenge, new byte[0]);
                param.RpName = "";
                param.UserName = "";
                param.UserDisplayName = "";
                param.Option_rk = false;
                // pinが未設定であればUVはtrue
                param.Option_uv = string.IsNullOrEmpty(pin);

                g.FIDO2.Attestation att = null;
                {
                    var res = await con.MakeCredentialAsync(param, pin);
                    if (res?.CTAPResponse?.Status == 0 && res?.CTAPResponse?.Attestation != null) {
                        att = res.CTAPResponse.Attestation;
                    }
                }

                if (con is BLEAuthenticatorConnector) {
                    (con as BLEAuthenticatorConnector).Disconnect();
                }

                return att;
            });
        }

        public async Task<g.FIDO2.Assertion> Authenticate(g.FIDO2.CTAP.AuthenticatorConnector con, string rpid, byte[] challenge, byte[] credentialId, string pin)
        {
            return await Task<g.FIDO2.Assertion>.Run(async () => {
                var assertion = new g.FIDO2.Assertion();
                {
                    var param = new g.FIDO2.CTAP.CTAPCommandGetAssertionParam(rpid, challenge, credentialId);
                    param.Option_up = true;
                    // pinが未設定であればUVはtrue
                    param.Option_uv = string.IsNullOrEmpty(pin);

                    var res = await con.GetAssertionAsync(param, pin);

                    if (res?.CTAPResponse?.Assertion != null) {
                        assertion = res.CTAPResponse.Assertion;
                    }

                    if (res?.CTAPResponse?.Assertion?.NumberOfCredentials > 0) {
                        for (int intIc = 0; intIc < res.CTAPResponse.Assertion.NumberOfCredentials - 1; intIc++) {
                            var next = await con.GetNextAssertionAsync();
                        }
                    }
                }

                return assertion;
            });
        }
    }

}
