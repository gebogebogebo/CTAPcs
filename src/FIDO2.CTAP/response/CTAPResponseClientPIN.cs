using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.CTAP
{
    public class CTAPResponseClientPIN : CTAPResponse
    {
        public CTAPResponseClientPIN() : base() { }
        public CTAPResponseClientPIN(CTAPResponse obj) : base(obj) { }

        public override void Parse(byte[] byteresponse)
        {
            var cbor = this.decodeFromBytes(byteresponse);
            if (cbor == null) return;
        }
    }

    public class CTAPResponseClientPIN_getRetries : CTAPResponseClientPIN
    {
        public int RetryCount { get; private set; }

        public override void Parse(byte[] byteresponse)
        {
            var cbor = this.decodeFromBytes(byteresponse);
            if (cbor == null) return;
            var obj = getObj(cbor, 0x03);
            RetryCount = (int)obj?.ToObject<UInt16>();
        }
    }

    public class CTAPResponseClientPIN2_getKeyAgreement : CTAPResponseClientPIN
    {
        public COSE_Key KeyAgreement { get; private set; }

        public override void Parse(byte[] byteresponse)
        {
            var cbor = this.decodeFromBytes(byteresponse);
            if (cbor == null) return;
            var obj = getObj(cbor, 0x01);
            this.KeyAgreement = new COSE_Key(obj);
        }
    }

    public class CTAPResponseClientPIN_getPINToken : CTAPResponseClientPIN
    {
        public byte[] PinToken { get; private set; }

        private byte[] pinTokenEnc;
        private byte[] sharedSecret;

        public CTAPResponseClientPIN_getPINToken(CTAPResponse obj) : base(obj) { }

        public CTAPResponseClientPIN_getPINToken(byte[] sharedSecret) : base()
        {
            this.sharedSecret = sharedSecret.ToArray();
        }

        public override void Parse(byte[] byteresponse)
        {
            var cbor = this.decodeFromBytes(byteresponse);
            if (cbor == null) return;
            var obj = getObj(cbor, 0x02);
            pinTokenEnc = obj?.GetByteString();

            computePinToken();
        }

        private void computePinToken()
        {
            PinToken = AES256CBC.Decrypt(sharedSecret, pinTokenEnc);
        }
    }

}
