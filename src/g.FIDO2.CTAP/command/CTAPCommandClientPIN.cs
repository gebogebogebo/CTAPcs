using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;
using System.Security.Cryptography;

namespace g.FIDO2.CTAP
{
    internal class CTAPCommandClientPIN : CTAPCommand
    {
        public enum ClientPINSubCommand
        {
            getRetries = 0x01,
            getKeyAgreement = 0x02,
            setPIN = 0x03,
            changePIN = 0x04,
            getPINToken = 0x05,
        };

        private ClientPINSubCommand subCommand;

        public CTAPCommandClientPIN(ClientPINSubCommand subCommand) : base()
        {
            this.subCommand = subCommand;
        }

        public override byte[] CreatePayload()
        {
            var cbor = CBORObject.NewMap();

            // 0x01:pinProtocol = 1固定
            cbor.Add(0x01, 1);

            switch (subCommand) {
                case ClientPINSubCommand.getRetries:
                    // 0x02:subCommand = 0x01:getRetries
                    cbor.Add(0x02, 0x01);
                    break;
                case ClientPINSubCommand.getKeyAgreement:
                    // 0x02:subCommand = 0x02:getKeyAgreement
                    cbor.Add(0x02, 0x02);
                    break;
                case ClientPINSubCommand.setPIN:
                    break;
                case ClientPINSubCommand.changePIN:
                    break;
                case ClientPINSubCommand.getPINToken:
                    break;
            }

            return create(CTAPCommandType.authenticatorClientPIN, cbor);
        }

        public static byte[] CreateSharedSecret(COSE_Key keyAgreement,out COSE_Key myKeyAgreement)
        {
            // sharedSecretを生成する(32byte)
            byte[] bG_x, bG_y;
            var sharedSecret = ECDH.CreateSharedSecret(keyAgreement.X, keyAgreement.Y, out bG_x, out bG_y);

            myKeyAgreement = new COSE_Key(2, -7, 1, bG_x, bG_y);

            return (sharedSecret);
        }

        public static byte[] CreatePinHashEnc(string pin, byte[] sharedSecret)
        {
            // AES256-CBC(sharedSecret, IV=0, LEFT(SHA-256(PIN), 16))

            // pinsha = SHA-256(PIN) ->32byte
            byte[] pinbyte = Encoding.ASCII.GetBytes(pin);
            SHA256 sha = new SHA256CryptoServiceProvider();
            byte[] pinsha = sha.ComputeHash(pinbyte);

            // pinsha16 = LEFT 16(pinsha)
            byte[] pinsha16 = pinsha.ToList().Skip(0).Take(16).ToArray();

            // pinHashEnc = AES256-CBC(sharedSecret, IV=0, pinsha16)
            string key = Common.BytesToHexString(sharedSecret);
            string data = Common.BytesToHexString(pinsha16);

            var pinHashEnc = AES256CBC.Encrypt(sharedSecret, pinsha16);

            return (pinHashEnc);
        }

        /*
        public static byte[] CreatePinAuth(byte[] sharedSecret, byte[] cdh, byte[] pinToken)
        {
            var pinTokenDec = AES256CBC.Decrypt(sharedSecret, pinToken);

            // HMAC-SHA-256(pinToken, clientDataHash)
            byte[] pinAuth;
            using (var hmacsha256 = new HMACSHA256(pinTokenDec)) {
                var dgst = hmacsha256.ComputeHash(cdh);
                pinAuth = dgst.ToList().Take(16).ToArray();
            }
            return (pinAuth);
        }
        */
        public static byte[] CreatePinAuth(byte[] cdh, byte[] pinToken)
        {
            if (cdh == null || pinToken == null) return null;

            // HMAC-SHA-256(pinToken, clientDataHash)
            byte[] pinAuth;
            using (var hmacsha256 = new HMACSHA256(pinToken)) {
                var dgst = hmacsha256.ComputeHash(cdh);
                pinAuth = dgst.ToList().Take(16).ToArray();
            }
            return (pinAuth);
        }

        public static byte[] CreatePinAuthforSetPin(byte[] sharedSecret, string newpin)
        {
            var newpin64 = PaddingPin64(newpin);

            var newPinEnc = AES256CBC.Encrypt(sharedSecret, newpin64);

            // HMAC-SHA-256(sharedSecret, newPinEnc)
            byte[] pinAuth;
            using (var hmacsha256 = new HMACSHA256(sharedSecret)) {
                var dgst = hmacsha256.ComputeHash(newPinEnc);
                pinAuth = dgst.ToList().Take(16).ToArray();
            }
            return (pinAuth);
        }

        public static byte[] CreatePinAuthforChangePin(byte[] sharedSecret, string newpin, string currentpin)
        {
            // new pin
            byte[] newPinEnc = null;
            {
                var newpin64 = PaddingPin64(newpin);
                newPinEnc = AES256CBC.Encrypt(sharedSecret, newpin64);
            }

            // current pin
            var currentPinHashEnc = CreatePinHashEnc(currentpin, sharedSecret);

            // source data
            var data = new List<byte>();
            data.AddRange(newPinEnc.ToArray());
            data.AddRange(currentPinHashEnc.ToArray());

            // HMAC-SHA-256(sharedSecret, newPinEnc)
            byte[] pinAuth;
            using (var hmacsha256 = new HMACSHA256(sharedSecret)) {
                var dgst = hmacsha256.ComputeHash(data.ToArray());
                pinAuth = dgst.ToList().Take(16).ToArray();
            }
            return (pinAuth);
        }

        public static byte[] PaddingPin64(string pin)
        {
            // 5.5.5. Setting a New PIN
            // 5.5.6. Changing existing PIN
            // During encryption, 
            // newPin is padded with trailing 0x00 bytes and is of minimum 64 bytes length. 
            // This is to prevent leak of PIN length while communicating to the authenticator. 
            // There is no PKCS #7 padding used in this scheme.
            var bpin64 = new byte[64];
            byte[] pintmp = Encoding.ASCII.GetBytes(pin);
            for (int intIc = 0; intIc < bpin64.Length; intIc++) {
                if (intIc < pintmp.Length) {
                    bpin64[intIc] = pintmp[intIc];
                } else {
                    bpin64[intIc] = 0x00;
                }
            }
            return (bpin64);
        }

        // newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
        public static byte[] CreateNewPinEnc(byte[] sharedSecret, string newpin)
        {
            return (createNewPinEnc(sharedSecret, PaddingPin64(newpin)));
        }
        private static byte[] createNewPinEnc(byte[] sharedSecret, byte[] newpin64)
        {
            byte[] newPinEnc = AES256CBC.Encrypt(sharedSecret, newpin64);
            return (newPinEnc);
        }

    }

    internal class CTAPCommandClientPIN_getRetries : CTAPCommandClientPIN
    {
        public CTAPCommandClientPIN_getRetries() : base(ClientPINSubCommand.getRetries) { }
    }

    internal class CTAPCommandClientPIN_getKeyAgreement : CTAPCommandClientPIN
    {
        public CTAPCommandClientPIN_getKeyAgreement() : base(ClientPINSubCommand.getKeyAgreement) { }
    }

    internal class CTAPCommandClientPIN_getPINToken : CTAPCommandClientPIN
    {
        private COSE_Key keyAgreement { get; set; }
        private byte[] pinHashEnc { get; set; }

        public CTAPCommandClientPIN_getPINToken(COSE_Key keyAgreement, byte[] pinHashEnc) : base(ClientPINSubCommand.getPINToken)
        {
            this.keyAgreement = keyAgreement;
            this.pinHashEnc = pinHashEnc.ToArray();
        }

        public override byte[] CreatePayload()
        {
            var cbor = CBORObject.NewMap();

            // 0x01:pinProtocol = 1固定
            cbor.Add(0x01, 1);

            // 0x02:subCommand = 0x03:setPIN
            cbor.Add(0x02, 0x05);

            // 0x03:keyAgreement : COSE_Key
            {
                var user = CBORObject.NewMap();
                user.Add(1, keyAgreement.Kty);
                user.Add(3, keyAgreement.Alg);
                user.Add(-1, keyAgreement.Crv);
                user.Add(-2, keyAgreement.X);
                user.Add(-3, keyAgreement.Y);
                cbor.Add(0x03, user);
            }

            // 0x06:
            cbor.Add(0x06, pinHashEnc);

            return create(CTAPCommandType.authenticatorClientPIN, cbor);
        }

    }

    internal class CTAPCommandClientPIN_changePIN : CTAPCommandClientPIN
    {
        private COSE_Key keyAgreement { get; set; }
        private byte[] pinAuth { get; set; }
        private byte[] newPinEnc { get; set; }
        private byte[] pinHashEnc { get; set; }

        public CTAPCommandClientPIN_changePIN(COSE_Key keyAgreement, byte[] pinAuth, byte[] newPinEnc, byte[] pinHashEnc) : base(ClientPINSubCommand.changePIN)
        {
            this.keyAgreement = keyAgreement;
            this.pinAuth = pinAuth?.ToArray();
            this.newPinEnc = newPinEnc?.ToArray();
            this.pinHashEnc = pinHashEnc?.ToArray();
        }

        public override byte[] CreatePayload()
        {
            var cbor = CBORObject.NewMap();

            // 0x01:pinProtocol = 1固定
            cbor.Add(0x01, 1);

            // 0x02:subCommand = 0x04:changePIN
            cbor.Add(0x02, 0x04);

            // 0x03:keyAgreement : COSE_Key
            {
                var user = CBORObject.NewMap();
                user.Add(1, keyAgreement.Kty);
                user.Add(3, keyAgreement.Alg);
                user.Add(-1, keyAgreement.Crv);
                user.Add(-2, keyAgreement.X);
                user.Add(-3, keyAgreement.Y);
                cbor.Add(0x03, user);
            }

            // 0x04:pinAuth
            cbor.Add(0x04, pinAuth);

            // 0x05:newPinEnc
            cbor.Add(0x05, newPinEnc);

            // 0x06:pinHashEnc
            cbor.Add(0x06, pinHashEnc);

            return create(CTAPCommandType.authenticatorClientPIN, cbor);
        }

    }

    internal class CTAPCommandClientPIN_setPIN : CTAPCommandClientPIN
    {
        private COSE_Key keyAgreement { get; set; }
        private byte[] pinAuth { get; set; }
        private byte[] newPinEnc { get; set; }

        public CTAPCommandClientPIN_setPIN(COSE_Key keyAgreement, byte[] pinAuth, byte[] newPinEnc) : base(ClientPINSubCommand.setPIN)
        {
            this.keyAgreement = keyAgreement;
            this.pinAuth = pinAuth?.ToArray();
            this.newPinEnc = newPinEnc?.ToArray();
        }

        public override byte[] CreatePayload()
        {
            var cbor = CBORObject.NewMap();

            // 0x01:pinProtocol = 1固定
            cbor.Add(0x01, 1);

            // 0x02:subCommand = 0x03:setPIN
            cbor.Add(0x02, 0x03);

            // 0x03:keyAgreement : COSE_Key
            {
                var user = CBORObject.NewMap();
                user.Add(1, keyAgreement.Kty);
                user.Add(3, keyAgreement.Alg);
                user.Add(-1, keyAgreement.Crv);
                user.Add(-2, keyAgreement.X);
                user.Add(-3, keyAgreement.Y);
                cbor.Add(0x03, user);
            }

            // 0x04:pinAuth
            cbor.Add(0x04, pinAuth);

            // 0x05:newPinEnc
            cbor.Add(0x05, newPinEnc);

            return create(CTAPCommandType.authenticatorClientPIN, cbor);
        }
    }

}
