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

namespace xClient
{
    /// <summary>
    /// Page11.xaml の相互作用ロジック
    /// </summary>
    public partial class Page11 : Page
    {
        private static Page21 page = null;

        public Page11(Attestation att)
        {
            InitializeComponent();

            var att_b = g.FIDO2.Serializer.Serialize(att);
            TextAttestation.Text = g.FIDO2.Common.BytesToHexString(att_b);
        }

        private void ButtonCopyAtt_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(this.TextAttestation.Text);
        }

        private void ButtonNext_Click(object sender, RoutedEventArgs e)
        {
            if (page == null) page = new Page21();
            this.NavigationService.Navigate(page);

        }
    }
}
