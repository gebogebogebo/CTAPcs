using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP.NFC
{
    internal class CTAPNFCSender
    {
        public CTAPNFCSender() { }

        public async Task<(DeviceStatus devSt, byte[] ctapRes)> SendCommandandResponseAsync(List<string> targetReaders, byte[] payload, int timeoutms)
        {
            var chk = CTAPNFC.CheckAP(targetReaders);
            if (string.IsNullOrEmpty(chk)) {
                Logger.Err("Connect Error");
                return (DeviceStatus.NotConnected, null);
            }

            var res = await CTAPNFC.SendCommandandResponse(targetReaders, payload);
            if (res == null) {
                Logger.Err("Response Error");
                return (DeviceStatus.Unknown, null);
            }
            /* timeoutはとれない？
            if (res.isTimeout) {
                Logger.Err("Wait Response Timeout");
                return (DeviceStatus.Timeout, null);
            }
            */
            return (DeviceStatus.Ok, res);

        }

    }
}
