using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.CTAP
{
    public class Attestation
    {
        public string Fmt { get; set; }
        public byte[] RpIdHash { get; set; }
        public bool Flags_UserPresentResult { get; set; }
        public bool Flags_UserVerifiedResult { get; set; }
        public bool Flags_AttestedCredentialDataIncluded { get; set; }
        public bool Flags_ExtensionDataIncluded { get; set; }
        public int SignCount { get; set; }
        public byte[] Aaguid { get; set; }
        public byte[] CredentialId { get; set; }
        public string CredentialPublicKey { get; set; }
        public byte[] CredentialPublicKeyByte { get; set; }
        public byte[] AuthData { get; set; }

        public int AttStmtAlg { get; set; }
        public byte[] AttStmtSig { get; set; }
        public byte[] AttStmtX5c { get; set; }
    }

    public class CTAPResponseMakeCredential : CTAPResponse
    {
        public Attestation Attestation { get; private set; }

        public CTAPResponseMakeCredential(CTAPResponse obj) : base(obj) { }
        public CTAPResponseMakeCredential() : base() { }

        internal override void Parse(byte[] byteresponse)
        {
            this.Attestation = new Attestation();

            var cbor = this.decodeFromBytes(byteresponse);
            if (cbor == null) return;

            foreach (var key in cbor.Keys) {
                var keyVal = key.ToObject<byte>();
                if (keyVal == 0x01) {
                    // fmt
                    Attestation.Fmt = cbor[key].AsString();
                } else if (keyVal == 0x02) {
                    // authData
                    parseAuthData(cbor[key].GetByteString());
                } else if (keyVal == 0x03) {
                    // attstmt
                    parseAttstmt(cbor[key]);
                }
            }
        }

        private void parseAuthData(byte[] data)
        {
            int index = 0;

            // rpIdHash	(32)
            Attestation.RpIdHash = data.Skip(index).Take(32).ToArray();
            index = index + 32;

            // flags(1)
            {
                byte flags = data[index];
                index++;
                Attestation.Flags_UserPresentResult = Common.GetBit(flags, 0);
                Attestation.Flags_UserVerifiedResult = Common.GetBit(flags, 2);
                Attestation.Flags_AttestedCredentialDataIncluded = Common.GetBit(flags, 6);
                Attestation.Flags_ExtensionDataIncluded = Common.GetBit(flags, 7);
            }

            // signCount(4)
            {
                Attestation.SignCount = Common.ToInt32(data, index, true);
                index = index + 4;
            }

            // aaguid	16
            Attestation.Aaguid = data.Skip(index).Take(16).ToArray();
            index = index + 16;

            // credentialId
            {
                int credentialIdLength = Common.ToInt16(data, index, true);
                index = index + 2;

                Attestation.CredentialId = data.Skip(index).Take(credentialIdLength).ToArray();
                index = index + credentialIdLength;
            }

            // credentialPublicKey
            {
                Attestation.CredentialPublicKeyByte = data.Skip(index).ToArray();
                var credentialPublicKeyCobr = CBORObject.DecodeFromBytes(Attestation.CredentialPublicKeyByte, CBOREncodeOptions.Default);
                Attestation.CredentialPublicKey = credentialPublicKeyCobr.ToJSONString();
                Logger.Log("credentialPublicKeyCobr:" + Attestation.CredentialPublicKey);
            }

            Attestation.AuthData = data.ToArray();
        }

        private void parseAttstmt(CBORObject attestationStatementCbor)
        {
            var attestationStatement = attestationStatementCbor.ToJSONString();
            Logger.Log("attestationStatement:" + attestationStatement);

            foreach (var key in attestationStatementCbor.Keys) {
                var keyVal = key.AsString();
                if (keyVal == "alg") {
                    Attestation.AttStmtAlg = attestationStatementCbor[key].ToObject<Int16>();
                } else if (keyVal == "sig") {
                    Attestation.AttStmtSig = attestationStatementCbor[key].GetByteString();
                } else if (keyVal == "x5c") {
                    foreach (var sub in attestationStatementCbor[key].Values) {
                        Attestation.AttStmtX5c = sub.GetByteString();
                        break;
                    }
                }
            }

        }
    }
}
