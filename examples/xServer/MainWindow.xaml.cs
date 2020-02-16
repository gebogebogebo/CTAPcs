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
using System.Windows.Threading;

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

        private void addLog(string message)
        {
            Console.WriteLine($"{message}");
            // UIスレッドで実行するおまじない
            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(() => {
                textLog.Text += message + Environment.NewLine;
            }));
        }

        private void ButtonCreateChallenge_Click(object sender, RoutedEventArgs e)
        {
            var rpid = this.TextRPID.Text;
            var challenge = AttestationVerifier.CreateChallenge();
            this.TextChallenge.Text = Common.BytesToHexString(challenge);

        }

        private void ButtonVerifyAttestation_Click(object sender, RoutedEventArgs e)
        {
            var challenge = Common.HexStringToBytes(this.TextChallenge.Text);

            var att_b = Common.HexStringToBytes(this.TextAttestation.Text);
            var att = g.FIDO2.Serializer.DeserializeAttestation(att_b);

            if (att != null) {
                var v = new g.FIDO2.Util.AttestationVerifier();
                var verify = v.Verify(challenge, att);

                addLog($"Verify  = {verify.IsSuccess}\r\n");
                if (verify.IsSuccess) {
                    addLog($"- CredentialID = \r\n{Common.BytesToHexString(verify.CredentialID)}\r\n");
                    addLog($"- PublicKey = \r\n{verify.PublicKeyPem}\r\n");
                }
            } else {
                addLog($"Attestaion Deserialize Error");
            }

        }
    }
}
