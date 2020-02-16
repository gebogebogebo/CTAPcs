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
using g.FIDO2.CTAP.HID;

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

        private async void ButtonRegisterHID_Click(object sender, RoutedEventArgs e)
        {
            // server
            var rpid = this.TextRPID.Text;
            var challenge = Common.HexStringToBytes(this.TextChallenge.Text);

            // client
            var att = new g.FIDO2.Attestation();
            {
                var con = new HIDAuthenticatorConnector();

                var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid, challenge);
                param.RpName = "test name";
                param.UserId = new byte[0];
                param.UserName = "testUserName";
                param.UserDisplayName = "testUserDisplayName";
                param.Option_rk = false;
                param.Option_uv = false;

                string pin = "1234";

                var res = await con.MakeCredentialAsync(param, pin);
                if (res?.CTAPResponse?.Attestation != null) {
                    att = res.CTAPResponse.Attestation;
                }

            }

        }
    }
}
