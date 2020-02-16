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
using g.FIDO2.Util;

namespace xServer
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

        private void ButtonCreateChallenge_Click(object sender, RoutedEventArgs e)
        {
            var rpid = this.TextRPID.Text;
            var challenge = AttestationVerifier.CreateChallenge();
            this.TextChallenge.Text = Common.BytesToHexString(challenge);

        }
    }
}
