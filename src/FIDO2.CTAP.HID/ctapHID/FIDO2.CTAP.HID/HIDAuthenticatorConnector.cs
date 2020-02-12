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
        List<HidParam> hidParams;

        internal override async Task<CTAPResponse> sendCommandandResponseAsync(CTAPCommand cmd, CTAPResponse res)
        {
            try {
                // 送信コマンドを作成(byte[])
                var payload = cmd.CreatePayload();

                // 送信して、応答受信(byte[])
                var sender = new CTAPHIDSender();
                var response = await sender.SendCommandandResponseAsync(hidParams, payload, 10000);

                // 応答をパース
                res.Parse(response);
                res.SendPayloadJson = cmd.PayloadJson;

                return res;
            } catch (Exception ex) {
                Logger.Log($"Exception...{ex.Message})");
                return null;
            }
        }

    }
}
