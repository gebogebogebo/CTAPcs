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
using g.FIDO2;
using g.FIDO2.Util;

namespace xServer
{
    /// <summary>
    /// Page3.xaml の相互作用ロジック
    /// </summary>
    public partial class Page3 : Page
    {
        private static Page4 page4 = null;

        public Page3(string challenge)
        {
            InitializeComponent();

            this.TextChallenge.Text = challenge;

        }

        private void ButtonNext_Click(object sender, RoutedEventArgs e)
        {
            if(string.IsNullOrEmpty(this.TextAttestation.Text)) {
                if (page4 == null) {
                    page4 = new Page4(null, "");
                }
                this.NavigationService.Navigate(page4);
            }

            var challenge = Common.HexStringToBytes(this.TextChallenge.Text);
            var att_b = Common.HexStringToBytes(this.TextAttestation.Text);
            var att = g.FIDO2.Serializer.DeserializeAttestation(att_b);

            if (att != null) {
                var v = new g.FIDO2.Util.AttestationVerifier();
                var verify = v.Verify(challenge, att);

                //addLog($"Verify  = {verify.IsSuccess}\r\n");
                if (verify.IsSuccess) {
                    //addLog($"- CredentialID = \r\n{Common.BytesToHexString(verify.CredentialID)}\r\n");
                    //addLog($"- PublicKey = \r\n{verify.PublicKeyPem}\r\n");

                    if (page4 == null) {
                        page4 = new Page4(verify.CredentialID,verify.PublicKeyPem);
                    }
                    this.NavigationService.Navigate(page4);

                }
            } else {
                //addLog($"Attestaion Deserialize Error");
            }

        }
    }
}
