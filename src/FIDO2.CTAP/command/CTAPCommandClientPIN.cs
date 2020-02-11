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
            string aG_x = BitConverter.ToString(keyAgreement.X).Replace("-", string.Empty);
            string aG_y = BitConverter.ToString(keyAgreement.Y).Replace("-", string.Empty);

            var bG_x = new StringBuilder(256);
            var bG_y = new StringBuilder(256);
            var strSharedSecret = new StringBuilder(256);

            int st = ECDH.CreateSharedSecret(aG_x, aG_y, bG_x, bG_y, strSharedSecret);

            // byte配列(32)にする
            var sharedSecret = Common.HexStringToBytes(strSharedSecret.ToString());

            myKeyAgreement = new COSE_Key(2, -7, 1, bG_x.ToString(), bG_y.ToString());

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

}
