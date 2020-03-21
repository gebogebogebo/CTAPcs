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
    /// Page2.xaml の相互作用ロジック
    /// </summary>
    public partial class Page2 : Page
    {
        private static Page3 page3 = null;
        private string rpid = "";

        public Page2()
        {
            InitializeComponent();

            this.rpid = this.TextRPID.Text;
            var challenge = AttestationVerifier.CreateChallenge();
            this.TextChallenge.Text = Common.BytesToHexString(challenge);
        }

        private void ButtonCopyRPID_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(this.TextRPID.Text);
        }

        private void ButtonCopyChallenge_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(this.TextChallenge.Text);
        }

        private void ButtonNext_Click(object sender, RoutedEventArgs e)
        {
            if (page3 == null) {
                page3 = new Page3(this.rpid,this.TextChallenge.Text);
            }
            this.NavigationService.Navigate(page3);
        }

    }
}
