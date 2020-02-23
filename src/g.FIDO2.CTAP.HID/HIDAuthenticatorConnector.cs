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
    public class HIDAuthenticatorConnector:AuthenticatorConnector
    {
        public int ReceiveResponseTimeoutmillisecond = 5000;

        /// <summary>
        /// KeepAlive event 
        /// </summary>
        public event EventHandler KeepAlive;

        /// <summary>
        /// constructor
        /// </summary>
        public HIDAuthenticatorConnector()
        {
            this.hidParams = HidParam.GetDefaultParams();
        }
        public HIDAuthenticatorConnector(HidParam hidParam)
        {
            this.hidParams = new List<HidParam>();
            this.hidParams.Add(hidParam);
        }

        public HIDAuthenticatorConnector(List<HidParam> hidParams)
        {
            this.hidParams = hidParams;
        }

        public bool IsConnected()
        {
            if (CTAPHID.find(this.hidParams)!=null) {
                return true;
            } else {
                return false;
            }
        }

        // private
        private List<HidParam> hidParams;

        public override async Task<(DeviceStatus devSt, CTAPResponse ctapRes)> sendCommandandResponseAsync(CTAPCommand cmd, CTAPResponse res)
        {
            try {
                // 送信コマンドを作成(byte[])
                var payload = cmd.CreatePayload();

                // 送信して、応答受信(byte[])
                var sender = new CTAPHIDSender();
                sender.KeepAlive += this.KeepAlive;
                var response = await sender.SendCommandandResponseAsync(hidParams, payload, ReceiveResponseTimeoutmillisecond);

                // 応答をパース
                if (response.ctapRes != null) {
                    res.Parse(response.ctapRes);
                }
                res.SendPayloadJson = cmd.PayloadJson;

                return (response.devSt,res);
            } catch (Exception ex) {
                Logger.Log($"Exception...{ex.Message})");
                return (DeviceStatus.Unknown,null);
            }
        }

    }
}
