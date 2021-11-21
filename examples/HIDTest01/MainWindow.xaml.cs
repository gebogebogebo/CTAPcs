﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using g.FIDO2.CTAP.HID;

namespace HIDTest01
{
    /// <summary>
    /// MainWindow.xaml の相互作用ロジック
    /// </summary>
    public partial class MainWindow : Window
    {
        private void addLog(string message)
        {
            Console.WriteLine($"{message}");
            // UIスレッドで実行するおまじない
            var ignored = this.Dispatcher.BeginInvoke(DispatcherPriority.Normal, (Action)(() => {
                textLog.Text += message + Environment.NewLine;
            }));
        }

        private void LogResponse(g.FIDO2.CTAP.DeviceStatus devSt, g.FIDO2.CTAP.CTAPResponse res)
        {
            addLog($"- DeviceStatus = {devSt.ToString()}");
            addLog($"- CTAP Status = 0x{res?.Status.ToString("X")}");
            addLog($"- CTAP StatusMsg = {res?.StatusMsg}");
            addLog($"- CTAP SendPayloadJson = {res?.SendPayloadJson}");
            addLog($"- CTAP ResponseDataJson = {res?.ResponsePayloadJson}");
            addLog("");
        }

        private Dictionary<string, HIDAuthenticatorConnector> fidoDevices = new Dictionary<string, HIDAuthenticatorConnector>();
        private string CurrentDevicePath => lstDevices.SelectedItem?.ToString();

        private void OnKeepAlive(object sender, EventArgs e)
        {
            addLog($"<OnKeepAlive>");
            addLog($"- touch authenticator!");
        }

        public MainWindow()
        {
            InitializeComponent();
            PopulateFIDODeviceList();
        }

        private async void ButtonGetInfo_Click(object sender, RoutedEventArgs e)
        {
            addLog("<GetInfo>");
            var con = GetCurrentConnector();
            if (con is null) return;

            addLog($"Reading from {con.GetDeviceProductName()}");

            var res = await con.GetInfoAsync();
            LogResponse(res.DeviceStatus, res.CTAPResponse);
            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Unauthorized)
            {
                addLog("Excute Administrator ?");
                return;
            }
            else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.NotConnected)
            {
                addLog("FIDO Key Not Connected");
                return;
            }
            else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok)
            {
                if (res.CTAPResponse.Status == 0)
                {
                    addLog("Get CTAP Response");
                }
            }
        }

        private HIDAuthenticatorConnector GetCurrentConnector()
        {
            HIDAuthenticatorConnector con = null;
            if (fidoDevices.ContainsKey(CurrentDevicePath))
            {
                con = fidoDevices[CurrentDevicePath];
            }
            else
            {
                return null;
            }

            if (!con.IsConnected())
            {
                addLog($"Not connected to {CurrentDevicePath}");
                return null;
            }
            return con;
        }

        private void PopulateFIDODeviceList()
        {
            string restore = lstDevices.SelectedItem?.ToString();
            lstDevices.Items.Clear();

            ReadFIDODevices();

            foreach(var dev in fidoDevices.Keys)
            {
                lstDevices.Items.Add(dev);
            }

            if (!string.IsNullOrEmpty(restore))
                if (fidoDevices.ContainsKey(restore))
                    lstDevices.SelectedItem = restore;

            if (lstDevices.SelectedItem is null && lstDevices.Items.Count > 0)
                lstDevices.SelectedIndex = 0;

            ButtonGetInfo.IsEnabled = !(lstDevices.SelectedItem is null);
            ButtonClientPINgetRetries.IsEnabled = !(lstDevices.SelectedItem is null);
            ButtonGetAssertion.IsEnabled = !(lstDevices.SelectedItem is null);
            ButtonMakeCredential.IsEnabled = !(lstDevices.SelectedItem is null);
            ButtonClientPINchangePIN.IsEnabled = !(lstDevices.SelectedItem is null);
            ButtonClientPINsetPIN.IsEnabled = !(lstDevices.SelectedItem is null);
            ButtonIsConnected.IsEnabled = !(lstDevices.SelectedItem is null);
            ButtonReset.IsEnabled = !(lstDevices.SelectedItem is null);
            buttonWink.IsEnabled = !(lstDevices.SelectedItem is null);
        }

        private void ReadFIDODevices()
        {
            //Read all FIDO devices
            var devPaths = new List<string>();
            devPaths.AddRange(HIDAuthenticatorConnector.GetAllFIDODevicePaths());

            //Any new devices, add a new connector object for it to the collection
            foreach(var devPath in devPaths)
            {
                if (!fidoDevices.ContainsKey(devPath))
                {
                    fidoDevices[devPath] = new HIDAuthenticatorConnector(devPath);
                    fidoDevices[devPath].KeepAlive += OnKeepAlive;
                }
            }

            //Remove devices from the collection that are no longer present
            List<string> removedDevices = new List<string>();
            removedDevices.AddRange(fidoDevices.Keys.Where(k => !devPaths.Contains(k)));
            foreach(var toRemove in removedDevices)
            {
                fidoDevices[toRemove].KeepAlive -= OnKeepAlive;
                fidoDevices.Remove(toRemove);
            }
        }

        private async void ButtonClientPINgetRetries_Click(object sender, RoutedEventArgs e)
        {
            var con = GetCurrentConnector();
            if (con is null) return;
            addLog("<ClientPIN getRetries>");
            var res = await con.ClientPINgetRetriesAsync();
            LogResponse(res.DeviceStatus, res.CTAPResponse);

            if (res?.CTAPResponse != null)
            {
                addLog($"- RetryCount = {res.CTAPResponse.RetryCount}\r\n");
            }
        }

        private async void ButtonGetAssertion_Click(object sender, RoutedEventArgs e)
        {
            var con = GetCurrentConnector();
            if (con is null) return;
            addLog("<getAssertion>");

            var rpid = this.textBoxRPID.Text;
            var challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");
            //var creid = g.FIDO2.Common.HexStringToBytes("99F946F5EAC7F8F9D56FF1F791626143DCBB9450AAA102F4EDBFF6D9913E44E9161B7AE113EFC482DA6C22A9037840757D8DA9922233BCB99F0473528E6DD7E8");
            byte[] creid = null;
            if (!string.IsNullOrEmpty(textBoxCreID.Text)) {
                creid = g.FIDO2.Common.HexStringToBytes(textBoxCreID.Text);
            }

            var param = new g.FIDO2.CTAP.CTAPCommandGetAssertionParam(rpid, challenge,creid);
            param.Option_up = true;
            param.Option_uv = false;

            string pin = this.textBoxPIN.Text;

            var res = await con.GetAssertionAsync(param, pin);
            LogResponse(res.DeviceStatus,res.CTAPResponse);

            if (res?.CTAPResponse?.Assertion?.NumberOfCredentials > 0) {
                for (int intIc = 0; intIc < res.CTAPResponse.Assertion.NumberOfCredentials - 1; intIc++) {
                    var next = await con.GetNextAssertionAsync();
                    LogResponse(res.DeviceStatus, next.CTAPResponse);
                }
            }
        }

        private async void ButtonMakeCredential_Click(object sender, RoutedEventArgs e)
        {
            var con = GetCurrentConnector();
            if (con is null) return;
            addLog("<makeCredential>");

            var rpid = this.textBoxRPID.Text;
            var challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");
            var userid = System.Text.Encoding.ASCII.GetBytes("12345");

            var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid,challenge,userid);
            param.Option_rk = (bool)this.checkBoxRK.IsChecked;
            param.Option_uv = false;
            param.UserName = "user";
            param.UserDisplayName = "DispUser";

            string pin = this.textBoxPIN.Text;

            var res = await con.MakeCredentialAsync(param, pin);
            LogResponse(res.DeviceStatus,res.CTAPResponse);

            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.NotConnected) {
                addLog("FIDO Key Not Connected");
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Timeout) {
                addLog("UP or UV timeout");
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok) {
                if (res.CTAPResponse.Status == 0) {
                    if (res.CTAPResponse.Attestation != null) {
                        addLog("Get CTAP Response");

                        // verify (g.FIDO2.Util.dll)
                        // var att = res.CTAPResponse.Attestation;
                        //var v = new AttestationVerifier();
                        //var verify = v.Verify(challenge, att);

                        var creid = g.FIDO2.Common.BytesToHexString(res.CTAPResponse.Attestation.CredentialId);
                        addLog($"- CredentialID = {creid}\r\n");
                        textBoxCreID.Text = creid;
                    }
                }
            }

        }

        private async void ButtonClientPINchangePIN_Click(object sender, RoutedEventArgs e)
        {
            var con = GetCurrentConnector();
            if (con is null) return;
            var res = await con.ClientPINchangePINAsync("1234","9999");
            LogResponse(res.DeviceStatus,res.CTAPResponse);
        }

        private async void ButtonClientPINsetPIN_Click(object sender, RoutedEventArgs e)
        {
            var con = GetCurrentConnector();
            if (con is null) return;
            string pin = this.textBoxPIN.Text;
            var res = await con.ClientPINsetPINAsync(pin);
            LogResponse(res.DeviceStatus,res.CTAPResponse);
        }

        private void ButtonIsConnected_Click(object sender, RoutedEventArgs e)
        {
            var con = GetCurrentConnector();
            addLog("<IsConnected>");
            bool res = false;
            if(!(con is null) && con.IsConnected())
                res = true;
            addLog($"- Connected = {res}\r\n");
        }

        private async void ButtonReset_Click(object sender, RoutedEventArgs e)
        {
            var con = GetCurrentConnector();
            if (con is null) return;
            addLog("<Reset>");
            var res = await con.ResetAsync();
            LogResponse(res.DeviceStatus, res.CTAPResponse);
        }

        private async void ButtonWink_Click(object sender, RoutedEventArgs e)
        {
            var con = GetCurrentConnector();
            if (con is null) return;
            addLog("<Wink x 5 >");
            for (int intIc = 0; intIc < 5; intIc++) {
                addLog("Wink...");
                var ret = await con.WinkAsync();
                await Task.Delay(1000);
            }
            addLog("<Wink - END >");
        }

        private void ButtonFinds_Click(object sender, RoutedEventArgs e)
        {
            addLog("<List HID>");
            PopulateFIDODeviceList();

            foreach (var dev in fidoDevices.Keys)
            {
                addLog(fidoDevices[dev].ToString());
            }
            addLog("<List HID - END>");
        }

        private void ButtonClear_Click(object sender, RoutedEventArgs e)
        {
            textLog.Text = "";
        }
    }
}
