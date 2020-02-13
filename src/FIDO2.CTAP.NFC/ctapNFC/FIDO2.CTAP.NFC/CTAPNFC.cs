using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP.NFC
{
    internal class CTAPNFC
    {
        public static byte[] GetCardUID(List<string> targetReaders)
        {
            byte[] uid = null;
            try {
                using (var reader = new ICReader(targetReaders)) {
                    // CONNECT
                    if (reader.Connect() == false) {
                        throw (new Exception("Connect Error"));
                    }

                    // get UID
                    var response = reader.SendandResponse(new byte[] { 0xFF, 0xCA, 0x00, 0x00, 0x00 });
                    if (response.IsSuccess) {
                        uid = response.Data;
                    }
                }
            } catch (Exception) {
            }
            return (uid);
        }

        public static string CheckAP(List<string> targetReaders)
        {
            string ret = "";
            var apdures = sendCommandandResponse(targetReaders, null);
            if (apdures != null && apdures.IsSuccess == true) {
                ret = System.Text.Encoding.ASCII.GetString(apdures.Data);
            }
            return (ret);
        }

        public static async Task<byte[]> SendCommandandResponse(List<string> targetReaders, byte[] send)
        {
            return await Task.Run(async () => {
                byte[] res = null;
                var apdures = sendCommandandResponse(targetReaders, send);
                if (apdures != null && apdures.IsSuccess == true) {
                    res = apdures.Data;
                }
                return (res);
            });
        }

        private static APDUresponse sendCommandandResponse(List<string> targetReaders, byte[] send)
        {
            try {
                // 8.2.5. Fragmentation
                var sends = new List<byte[]>();
                if( send != null) {
                    if (send.Length > 0xff) {
                        List<byte> tmp = new List<byte>();
                        tmp.AddRange(send);

                        var devides = tmp.Select((v, i) => new { v, i })
                            .GroupBy(x => x.i / 0xff)
                            .Select(g => g.Select(x => x.v));

                        foreach (var dev in devides) {
                            sends.Add(dev.ToArray());
                        }
                    } else {
                        sends.Add(send);
                    }
                }

                using (var reader = new ICReader(targetReaders)) {
                    // CONNECT
                    if (reader.Connect() == false)
                        throw (new Exception("Connect Error"));

                    APDUresponse res;
                    // SELECT AP
                    {
                        var apdu = new List<byte>();
                        var ap = new byte[] { 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01 };

                        apdu.AddRange(new List<byte> { 0x00, 0xA4, 0x04, 0x00 });
                        apdu.Add((byte)ap.Length);
                        apdu.AddRange(ap);
                        apdu.Add(0x00);

                        res = reader.SendandResponse(apdu.ToArray());
                        if( send == null) {
                            return res;
                        }
                    }

                    // send command
                    foreach( var senddata in sends.Select((v, i) => new { v, i })) {

                        var apdu = new List<byte>();

                        if( senddata.i == sends.Count()-1) {
                            // last
                            apdu.Add(0x80);
                        } else {
                            apdu.Add(0x90);
                        }

                        apdu.AddRange(new List<byte> { 0x10, 0x00, 0x00 });
                        apdu.Add((byte)senddata.v.Length);
                        apdu.AddRange(senddata.v);
                        apdu.Add(0x00);

                        res = reader.SendandResponse(apdu.ToArray());
                        if (res.Sw1 == 0x61) {
                            // next
                            for (; ; ) {
                                var next = reader.SendandResponse(new byte[] { 0x80, 0xC0, 0x00, 0x00 });
                                res.Marge(next);
                                if (res.Sw1 != 0x61) {
                                    break;
                                }
                            }
                        }
                    }
                    return (res);
                }

            } catch (Exception) {
            }
            return (null);
        }

    }
}
