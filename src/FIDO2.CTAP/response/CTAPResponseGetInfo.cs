using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.CTAP
{
    public class CTAPResponseGetInfo:CTAPResponse
    {
        public enum OptionFlag
        {
            absent,                             // 未対応
            present_and_set_to_false,           // 未設定
            present_and_set_to_true,            // 設定済み
        };

        public string[] Versions { get; private set; }
        public string[] Extensions { get; private set; }
        public byte[] Aaguid { get; private set; }
        public OptionFlag Option_rk { get; private set; }
        public OptionFlag Option_up { get; private set; }
        public OptionFlag Option_plat { get; private set; }
        public OptionFlag Option_clientPin { get; private set; }
        public OptionFlag Option_uv { get; private set; }
        public int MaxMsgSize { get; private set; }
        public int[] PinProtocols { get; private set; }

        public CTAPResponseGetInfo() : base() { }

        public override void Parse(byte[] byteresponse)
        {
            var cbor = this.decodeFromBytes(byteresponse);
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsByte();
                if (keyVal == 0x01) {
                    Versions = getKeyValueAsStringArray(cbor[key]);
                } else if (keyVal == 0x02) {
                    Extensions = getKeyValueAsStringArray(cbor[key]);
                } else if (keyVal == 0x03) {
                    Aaguid = cbor[key].GetByteString();
                } else if (keyVal == 0x04) {
                    Option_rk = getKeyValueAsOptionFlag(cbor[key], "rk");
                    Option_up = getKeyValueAsOptionFlag(cbor[key], "up");
                    Option_plat = getKeyValueAsOptionFlag(cbor[key], "plat");
                    Option_clientPin = getKeyValueAsOptionFlag(cbor[key], "clientPin");
                    Option_uv = getKeyValueAsOptionFlag(cbor[key], "uv");
                } else if (keyVal == 0x05) {
                    MaxMsgSize = cbor[key].AsInt16();
                } else if (keyVal == 0x06) {
                    PinProtocols = getKeyValueAsIntArray(cbor[key]);
                }
            }
        }

        private OptionFlag getKeyValueAsOptionFlag(CBORObject obj, string key)
        {
            bool? flag = getKeyValueAsBoolorNull(obj, key);
            if (flag == null) {
                return (OptionFlag.absent);
            } else if (flag == true) {
                return (OptionFlag.present_and_set_to_true);
            } else {
                return (OptionFlag.present_and_set_to_false);
            }
        }

    }
}
