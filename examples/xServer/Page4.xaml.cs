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
    /// Page4.xaml の相互作用ロジック
    /// </summary>
    public partial class Page4 : Page
    {
        public Page4(byte[] creid,string pubkey)
        {
            InitializeComponent();

            this.TextCredentialID.Text = Common.BytesToHexString(creid);
            this.TextPublickKey.Text = pubkey;
        }
    }
}
