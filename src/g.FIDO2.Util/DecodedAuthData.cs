using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.Util
{
    internal class DecodedAuthData
    {
        public byte[] RpIdHash;
        public bool Flags_UserPresentResult;
        public bool Flags_UserVerifiedResult;
        private bool Flags_AttestedCredentialDataIncluded;
        private bool Flags_ExtensionDataIncluded;
        public int SignCount;
        private byte[] Aaguid;
        public byte[] CredentialId;
        public string PublicKeyPem;

        public bool Decode(byte[] authData)
        {
            try {

                int index = 0;

                // rpIdHash	(32)
                RpIdHash = authData.Skip(index).Take(32).ToArray();
                index = index + 32;

                // flags(1)
                {
                    byte flags = authData[index];
                    index++;
                    Flags_UserPresentResult = Common.GetBit(flags, 0);
                    Flags_UserVerifiedResult = Common.GetBit(flags, 2);
                    Flags_AttestedCredentialDataIncluded = Common.GetBit(flags, 6);
                    Flags_ExtensionDataIncluded = Common.GetBit(flags, 7);
                }

                // signCount(4)
                {
                    SignCount = Common.ToInt32(authData, index, true);
                    index = index + 4;
                }

                // aaguid	16
                Aaguid = authData.Skip(index).Take(16).ToArray();
                index = index + 16;

                // credentialId
                {
                    int credentialIdLength = Common.ToInt16(authData, index, true);
                    index = index + 2;

                    CredentialId = authData.Skip(index).Take(credentialIdLength).ToArray();
                    index = index + credentialIdLength;
                }

                // credentialPublicKey
                {
                    var tmp = authData.Skip(index).ToArray();

                    // tmp -> cbors
                    //          [0] credentialPublicKey
                    //          [1] extensions
                    var cbors = CBORObject.DecodeSequenceFromBytes(tmp, CBOREncodeOptions.Default);
                    if (cbors.Count() > 0) {
                        var credentialPublicKeyByte = cbors[0].EncodeToBytes();
                        // PublickKeyをPEMに変換する
                        PublicKeyPem = this.convertCOSEtoPEM(credentialPublicKeyByte);
                    }
                }

                return true;
            } catch (Exception ex) {
                Logger.Err(ex, "Decode");
                return false;
            }
        }

        private string convertCOSEtoPEM(byte[] cose)
        {
            // COSE形式の公開鍵をPEM形式に変換する
            // 1-1.26byteのメタデータを追加
            // 1-2.0x04を追加
            // 1-3.COSEデータのxとyを追加
            // 2-1.Base64エンコード
            // 2-2.64文字ごとに改行コードをいれる
            // 2-3.ヘッダとフッタを入れる

            string pemdata = "";
            try {
                // Phase-1
                var pubkey = new List<byte>();
                var metaheader = Common.HexStringToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200");
                pubkey.AddRange(metaheader);

                pubkey.Add(0x04);
                var cbor = PeterO.Cbor.CBORObject.DecodeFromBytes(cose, PeterO.Cbor.CBOREncodeOptions.Default);
                foreach (var key in cbor.Keys) {
                    if (key.Type == CBORType.Integer) {
                        var keyVal = key.ToObject<Int16>();
                        if (keyVal == -2) {
                            var x = cbor[key].GetByteString();
                            pubkey.AddRange(x);
                        } else if (keyVal == -3) {
                            var y = cbor[key].GetByteString();
                            pubkey.AddRange(y);
                        }
                    }
                }

                // Phase-2
                pemdata = DerConverter.ToPemPublicKey(pubkey.ToArray());

            } catch (Exception) {

            }
            return (pemdata);
        }

    }

}
