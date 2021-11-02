using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP.HID
{
    /// <summary>
    /// Communication class with HID authenticator
    /// </summary>
    public class HIDAuthenticatorConnector : AuthenticatorConnector
    {
        public int ReceiveResponseTimeoutmillisecond = 5000;

        /// <summary>
        /// KeepAlive event 
        /// </summary>
        public event EventHandler KeepAlive;

        public HIDAuthenticatorConnector(string devicePath)
        {
            this.DevicePath = devicePath;
        }

        public bool IsConnected()
        {
            if (CTAPHID.Find(this.DevicePath) == null)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public async Task<bool> WinkAsync()
        {
            HidLibrary.IHidDevice hidDevice = null;

            try
            {
                hidDevice = CTAPHID.Find(DevicePath);
                if (hidDevice == null) return false;

                using (var openedDevice = await CTAPHID.OpenAsync(hidDevice))
                {
                    var ret = await openedDevice.WinkAsync(null);
                }
            }
            catch (Exception)
            {
                return false;
            }
            finally
            {
                hidDevice?.Dispose();
            }
            return true;
        }

        public string GetDevicePath()
        {
            var hid = CTAPHID.Find(DevicePath);
            if (hid is null) return string.Empty;

            return $"{hid.DevicePath}";
        }

        public string GetDeviceProductName()
        {
            var hid = CTAPHID.Find(DevicePath);
            if (hid is null) return string.Empty;
            var productBytes = new byte[(126 + 1) * 2];
            hid.ReadProduct(out productBytes);
            string productName = System.Text.Encoding.Unicode.GetString(productBytes);
            return productName;
        }

        public override string ToString()
        {
            var hid = CTAPHID.Find(DevicePath);
            if(hid is null) return string.Empty;
            return  $"{hid.DevicePath} - VendorId: {hid.Attributes.VendorHexId}, ProductId: {hid.Attributes.ProductHexId}, Description: '{hid.Description}'";
        }

        // private
        private string DevicePath;

        protected override async Task<(DeviceStatus devSt, CTAPResponse ctapRes)> sendCommandandResponseAsync(CTAPCommand cmd, CTAPResponse res)
        {
            try
            {
                // 送信コマンドを作成(byte[]) | Create send command
                var payload = cmd.CreatePayload();

                // 送信して、応答受信(byte[]) | Send and receive response
                var sender = new CTAPHIDSender();
                sender.KeepAlive += this.KeepAlive;
                var response = await sender.SendCommandandResponseAsync(DevicePath, payload, ReceiveResponseTimeoutmillisecond);

                // 応答をパース | Parse response
                if (response.ctapRes != null)
                {
                    res.Parse(response.ctapRes);
                }
                res.SendPayloadJson = cmd.PayloadJson;

                return (response.devSt, res);
            }
            catch (Exception ex)
            {
                Logger.Log($"Exception...{ex.Message})");
                return (DeviceStatus.Unknown, null);
            }
        }

        public static List<string> GetAllFIDODevicePaths()
        {
            List<string> devices = new List<string>();
            devices.AddRange(CTAPHID.GetAllFIDODevices().Select(d => d.DevicePath).ToList());
            return devices;
        }
    }
}
