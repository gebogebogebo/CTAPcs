using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.CTAP
{
    public class CTAPCommandGetAssertionParam
    {
        public string RpId { get; private set; }
        public byte[] ClientDataHash { get; private set; }
        public byte[] AllowList_CredentialId { get; private set; }
        public bool Option_up { get; set; }
        public bool Option_uv { get; set; }

        public CTAPCommandGetAssertionParam(string rpid,byte[] challenge,byte[] credentialid)
        {
            this.RpId = rpid;
            this.ClientDataHash = Common.CreateClientDataHash(challenge);
            this.AllowList_CredentialId = credentialid?.ToArray();
        }
    }

    internal class CTAPCommandGetAssertion : CTAPCommand
    {
        private CTAPCommandGetAssertionParam param { get; set; }
        private byte[] pinAuth { get; set; }

        public CTAPCommandGetAssertion(CTAPCommandGetAssertionParam param, byte[] pinAuth)
        {
            this.param = param;
            this.pinAuth = pinAuth?.ToArray();
        }

        public override byte[] CreatePayload()
        {
            var cbor = CBORObject.NewMap();

            // 0x01 : rpid
            cbor.Add(0x01, param.RpId);

            // 0x02 : clientDataHash
            cbor.Add(0x02, param.ClientDataHash);

            // 0x03 : allowList
            if (param.AllowList_CredentialId != null) {
                var pubKeyCredParams = CBORObject.NewMap();
                pubKeyCredParams.Add("type", "public-key");
                pubKeyCredParams.Add("id", param.AllowList_CredentialId);
                cbor.Add(0x03, CBORObject.NewArray().Add(pubKeyCredParams));
            }

            // 0x05 : options
            {
                var opt = CBORObject.NewMap();
                opt.Add("up", param.Option_up);
                opt.Add("uv", param.Option_uv);
                cbor.Add(0x05, opt);
            }

            if (pinAuth != null) {
                // pinAuth(0x06)
                cbor.Add(0x06, pinAuth);
                // 0x07:pinProtocol
                cbor.Add(0x07, 1);
            }

            return (create(CTAPCommandType.authenticatorGetAssertion, cbor));
        }

    }

}
