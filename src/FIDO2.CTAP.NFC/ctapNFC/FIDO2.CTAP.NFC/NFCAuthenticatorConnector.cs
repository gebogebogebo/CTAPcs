using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using g.FIDO2.CTAP;

namespace g.FIDO2.CTAP.NFC
{
    /// <summary>
    /// Communication class with NFC authenticator
    /// </summary>
    public class NFCAuthenticatorConnector : AuthenticatorConnector
    {
        public int ReceiveResponseTimeoutmillisecond = 5000;

        /// <summary>
        /// constructor
        /// </summary>
        public NFCAuthenticatorConnector()
        {
            this.targetReaders = NfcParam.GetDefalutReaders();
        }

        public bool IsConnected()
        {
            var chk = CTAPNFC.CheckAP(targetReaders);
            return !string.IsNullOrEmpty(chk);
        }

        private List<string> targetReaders;

        internal override async Task<(DeviceStatus devSt, CTAPResponse ctapRes)> sendCommandandResponseAsync(CTAPCommand cmd, CTAPResponse res)
        {
            try {
                // 送信コマンドを作成(byte[])
                var payload = cmd.CreatePayload();

                // 送信して、応答受信(byte[])
                var sender = new CTAPNFCSender();
                var response = await sender.SendCommandandResponseAsync(targetReaders, payload, ReceiveResponseTimeoutmillisecond);

                // 応答をパース
                if (response.ctapRes != null) {
                    res.Parse(response.ctapRes);
                }
                res.SendPayloadJson = cmd.PayloadJson;

                return (response.devSt, res);
            } catch (Exception ex) {
                Logger.Log($"Exception...{ex.Message})");
                return (DeviceStatus.Unknown, null);
            }
        }

    }
}
