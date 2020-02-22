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
            var challenge = Common.HexStringToBytes(this.TextChallenge.Text);
            var att_b = Common.HexStringToBytes(this.TextAttestation.Text);
            var att = Serializer.DeserializeAttestation(att_b);
            if( att == null) {
                // Attestaion Deserialize Error
                return;
            }

            // verify
            var v = new AttestationVerifier();
            var verify = v.Verify(challenge, att);

            if (verify.IsSuccess) {
                if (page4 == null) page4 = new Page4(verify.CredentialID, verify.PublicKeyPem);
                this.NavigationService.Navigate(page4);
            }
        }

        private void ButtonPasteAttestation_Click(object sender, RoutedEventArgs e)
        {
            this.TextAttestation.Paste();
        }
    }
}
