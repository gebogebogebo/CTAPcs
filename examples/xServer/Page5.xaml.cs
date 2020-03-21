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
    /// Page5.xaml の相互作用ロジック
    /// </summary>
    public partial class Page5 : Page
    {
        private static Page6 page6 = null;

        public Page5(byte[] creid, string pubkey)
        {
            InitializeComponent();

            var challenge = AttestationVerifier.CreateChallenge();
            this.TextChallenge.Text = Common.BytesToHexString(challenge);
            if(creid != null) this.TextCredentialID.Text = Common.BytesToHexString(creid);
            if(pubkey != null) this.TextPublickKey.Text = pubkey;

        }

        private void ButtonNext_Click(object sender, RoutedEventArgs e)
        {
            if (page6 == null) page6 = new Page6(this.TextRPID.Text,this.TextChallenge.Text, this.TextPublickKey.Text);
            this.NavigationService.Navigate(page6);
        }

        private void ButtonCopyRPID_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(this.TextRPID.Text);
        }

        private void ButtonCopyChallenge_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(this.TextChallenge.Text);
        }

        private void ButtonCopyCredentialID_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(this.TextCredentialID.Text);
        }
    }
}
