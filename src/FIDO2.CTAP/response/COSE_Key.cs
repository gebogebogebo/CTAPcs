using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.CTAP
{
    public class COSE_Key
    {
        // (Authenticator public key in COSE_Key format. )
        public int Kty { get; private set; }
        public int Alg { get; private set; }
        public int Crv { get; private set; }
        public byte[] X { get; private set; }
        public byte[] Y { get; private set; }

        public COSE_Key(CBORObject cbor)
        {
            parseCOSEkey(cbor);
        }

        public COSE_Key(int kty,int alg,int crv,byte[] x,byte[] y)
        {
            Kty = kty;
            Alg = alg;
            Crv = crv;
            X = (byte[])x.Clone();
            Y = (byte[])y.Clone();
        }

        public COSE_Key(int kty, int alg, int crv, string x, string y)
        {
            Kty = kty;
            Alg = alg;
            Crv = crv;
            X = Common.HexStringToBytes(x);
            Y = Common.HexStringToBytes(y);
        }

        /*
        private void parse(CBORObject cbor)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsByte();
                if (keyVal == 0x01) {
                    parseCOSEkey(cbor[key]);
                }
            }

        }
        */

        private void parseCOSEkey(CBORObject cbor)
        {
            var attestationStatement = cbor.ToJSONString();
            Logger.Log("keyAgreement:" + attestationStatement);

            foreach (var key in cbor.Keys) {
                var keyVal = key.AsInt16();

                if( keyVal == 1) {
                    Kty = cbor[key].AsInt16();
                } else if( keyVal == 3) {
                    Alg = cbor[key].AsInt16();
                } else if (keyVal == -1) {
                    Crv = cbor[key].AsInt16();
                } else if (keyVal == -2) {
                    X = cbor[key].GetByteString();
                } else if (keyVal == -3) {
                    Y = cbor[key].GetByteString();
                }
            }

        }


    }
}
