using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP.HID
{
    internal class CTAPHIDSender
    {
        public CTAPHIDSender() { }

        public async Task<byte[]> SendCommandandResponseAsync(List<HidParam> hidParams,byte[] payload, int timeoutms)
        {
            var res = await CTAPHID.SendCommandandResponse(hidParams,payload, timeoutms);
            if (res == null) {
                Logger.Err("Response Error");
                return null;
            }
            if (res.isTimeout) {
                Logger.Err("Wait Response Timeout");
                return null;
            }
            return res.responseData;
        }

    }
}
