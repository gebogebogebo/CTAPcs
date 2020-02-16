extern alias ctapHIDlib;

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
using System.Windows.Threading;
using ctapHIDlib.g.FIDO2.CTAP.HID;

namespace xClient
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

        private void LogResponse(ctapHIDlib.g.FIDO2.CTAP.DeviceStatus devSt, ctapHIDlib.g.FIDO2.CTAP.CTAPResponse res)
        {
            addLog($"- DeviceStatus = {devSt.ToString()}");
            addLog($"- CTAP Status = 0x{res?.Status.ToString("X")}");
            addLog($"- CTAP StatusMsg = {res?.StatusMsg}");
            //addLog($"- CTAP SendPayloadJson = {res?.SendPayloadJson}");
            //addLog($"- CTAP ResponseDataJson = {res?.ResponsePayloadJson}");
            addLog("");
        }

        private async void ButtonRegisterHID_Click(object sender, RoutedEventArgs e)
        {
            addLog("Register HID");

            // server
            var rpid = this.TextRPID.Text;
            var challenge = Common.HexStringToBytes(this.TextChallenge.Text);
            var pin = this.TextPIN.Text;

            // client
            g.FIDO2.Attestation att = null;
            {
                var con = new HIDAuthenticatorConnector();

                var param = new ctapHIDlib.g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid, challenge);
                param.RpName = "test name";
                param.UserId = new byte[0];
                param.UserName = "testUserName";
                param.UserDisplayName = "testUserDisplayName";
                param.Option_rk = false;
                param.Option_uv = false;

                var res = await con.MakeCredentialAsync(param, pin);
                LogResponse(res.DeviceStatus, res.CTAPResponse);
                if (res?.CTAPResponse?.Status==0 && res?.CTAPResponse?.Attestation != null) {
                    att = res.CTAPResponse.Attestation;
                }

            }

            if (att != null) {
                var att_b = g.FIDO2.Serializer.Serialize(att);

                addLog("Attestation ---");
                addLog(Common.BytesToHexString(att_b));
                addLog("--- Attestation");

            }
        }
    }
}
