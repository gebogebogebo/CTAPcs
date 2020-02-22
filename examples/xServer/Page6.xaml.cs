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
    /// Page6.xaml の相互作用ロジック
    /// </summary>
    public partial class Page6 : Page
    {
        private static Page7 page7 = null;

        public Page6(string challenge, string pubkey)
        {
            InitializeComponent();

            this.TextChallenge.Text = challenge;
            this.TextPublicKey.Text= pubkey;
        }

        private void ButtonNext_Click(object sender, RoutedEventArgs e)
        {
            var pubkey = this.TextPublicKey.Text;
            var challenge = Common.HexStringToBytes(this.TextChallenge.Text);
            var ass_b = Common.HexStringToBytes(this.TextAssertion.Text);
            var ass = g.FIDO2.Serializer.DeserializeAssertion(ass_b);
            if (ass == null) {
                // Deserialize Error
                return;
            }

            var v = new g.FIDO2.Util.AssertionVerifier();
            var verify = v.Verify(pubkey,challenge, ass);

            if (verify.IsSuccess) {
                if (page7 == null) page7 = new Page7();
                this.NavigationService.Navigate(page7);
            }
        }

        private void ButtonPasteAssertion_Click(object sender, RoutedEventArgs e)
        {
            this.TextAssertion.Paste();
        }
    }
}
