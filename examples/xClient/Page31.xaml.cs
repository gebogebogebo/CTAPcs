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
    /// Page31.xaml の相互作用ロジック
    /// </summary>
    public partial class Page31 : Page
    {
        private static Page32 page = null;

        public Page31(Assertion ass)
        {
            InitializeComponent();

            var ass_b = g.FIDO2.Serializer.Serialize(ass);
            TextAssertion.Text = g.FIDO2.Common.BytesToHexString(ass_b);
        }

        private void ButtonCopyAssertion_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(this.TextAssertion.Text);
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            if (page == null) page = new Page32();
            this.NavigationService.Navigate(page);
        }
    }
}
