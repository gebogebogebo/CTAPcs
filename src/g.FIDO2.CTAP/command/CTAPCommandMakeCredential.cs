using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.CTAP
{
    public class CTAPCommandMakeCredentialParam
    {
        public string RpId { get; private set; }
        public string RpName { get; set; }
        public byte[] UserId { get; set; }
        public string UserName { get; set; }
        public string UserDisplayName { get; set; }
        public bool Option_rk { get; set; }
        public bool Option_uv { get; set; }
        public byte[] ClientDataHash { get; private set; }

        public CTAPCommandMakeCredentialParam(string rpid, byte[] challenge)
        {
            this.RpId = rpid;
            this.ClientDataHash = Common.CreateClientDataHash(challenge);
        }
    }

    internal class CTAPCommandMakeCredential : CTAPCommand
    {
        private CTAPCommandMakeCredentialParam param { get; set; }
        private byte[] pinAuth { get; set; }

        public CTAPCommandMakeCredential(CTAPCommandMakeCredentialParam param,byte[] pinAuth)
        {
            this.param = param;
            this.pinAuth = pinAuth.ToArray();
        }

        public override byte[] CreatePayload()
        {
            var cbor = CBORObject.NewMap();

            // 0x01 : clientDataHash
            cbor.Add(0x01, param.ClientDataHash);

            // 0x02 : rp
            cbor.Add(0x02, CBORObject.NewMap().Add("id", param.RpId).Add("name", param.RpName));

            // 0x03 : user
            {
                var user = CBORObject.NewMap();
                user.Add("id", param.UserId);

                if (string.IsNullOrEmpty(param.UserName)) {
                    user.Add("name", " ");
                } else {
                    user.Add("name", param.UserName);
                }

                if (string.IsNullOrEmpty(param.UserDisplayName)) {
                    user.Add("displayName", " ");
                } else {
                    user.Add("displayName", param.UserDisplayName);
                }

                cbor.Add(0x03, user);
            }

            // 0x04 : pubKeyCredParams
            {
                var pubKeyCredParams = CBORObject.NewMap();
                pubKeyCredParams.Add("alg", -7);
                pubKeyCredParams.Add("type", "public-key");
                cbor.Add(0x04, CBORObject.NewArray().Add(pubKeyCredParams));
            }

            // 0x07 : options
            {
                var opt = CBORObject.NewMap();
                opt.Add("rk", param.Option_rk);
                opt.Add("uv", param.Option_uv);
                cbor.Add(0x07, opt);
            }

            if (pinAuth != null) {
                // pinAuth(0x08)
                cbor.Add(0x08, pinAuth);

                // 0x09:pinProtocol
                cbor.Add(0x09, 1);
            }

            return (create(CTAPCommandType.authenticatorMakeCredential, cbor));
        }

    }

}
