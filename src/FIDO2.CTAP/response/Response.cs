using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP
{
    public enum DeviceStatus
    {
        Ok = 0,
        NotConnedted = 1,
        Timeout = 2,
        Unauthorized = 3,
        Unknown = 999,
    };

    public class ResponseBase
    {
        public DeviceStatus DeviceStatus { get; private set; }
        public ResponseBase(DeviceStatus devst, CTAPResponse ctapres)
        {
            if( (ctapres == null || ctapres.Status != 0) && devst == DeviceStatus.Ok) {
                // この場合、アプリの権限の問題が怪しい
                if (!Common.IsAdministrator()){
                    devst = DeviceStatus.Unauthorized;
                }
            }

            this.DeviceStatus = devst;
        }
    }

    public class ResponseGetInfo : ResponseBase
    {
        public CTAPResponseGetInfo CTAPResponse { get; private set; }
        public ResponseGetInfo(DeviceStatus devst, CTAPResponse ctapres) : base(devst, ctapres) { this.CTAPResponse = ctapres as CTAPResponseGetInfo; }
    }

    public class ResponseClientPIN : ResponseBase
    {
        public CTAPResponseClientPIN CTAPResponse { get; private set; }
        public ResponseClientPIN(DeviceStatus devst, CTAPResponse ctapres) : base(devst, ctapres) { this.CTAPResponse = ctapres as CTAPResponseClientPIN; }
    }

    public class ResponseClientPIN_getRetries : ResponseBase
    {
        public CTAPResponseClientPIN_getRetries CTAPResponse { get; private set; }
        public ResponseClientPIN_getRetries(DeviceStatus devst, CTAPResponse ctapres) : base(devst, ctapres) { this.CTAPResponse = ctapres as CTAPResponseClientPIN_getRetries; }
    }

    public class ResponseClientPIN_getKeyAgreement : ResponseBase
    {
        public CTAPResponseClientPIN2_getKeyAgreement CTAPResponse { get; private set; }
        public ResponseClientPIN_getKeyAgreement(DeviceStatus devst, CTAPResponse ctapres) : base(devst, ctapres) { this.CTAPResponse = ctapres as CTAPResponseClientPIN2_getKeyAgreement; }
    }

    public class ResponseClientPIN_getPINToken : ResponseBase
    {
        public CTAPResponseClientPIN_getPINToken CTAPResponse { get; private set; }
        public ResponseClientPIN_getPINToken(DeviceStatus devst, CTAPResponse ctapres) : base(devst, ctapres) { this.CTAPResponse = ctapres as CTAPResponseClientPIN_getPINToken; }
    }

    public class ResponseGetAssertion : ResponseBase
    {
        public CTAPResponseGetAssertion CTAPResponse { get; private set; }
        public ResponseGetAssertion(DeviceStatus devst, CTAPResponse ctapres) : base(devst, ctapres)
        {
            if (ctapres is CTAPResponseGetAssertion) {
                this.CTAPResponse = ctapres as CTAPResponseGetAssertion;
            } else {
                this.CTAPResponse = new CTAPResponseGetAssertion(ctapres);
            }
        }
    }

    public class ResponseMakeCredential : ResponseBase
    {
        public CTAPResponseMakeCredential CTAPResponse { get; private set; }
        public ResponseMakeCredential(DeviceStatus devst, CTAPResponse ctapres) : base(devst, ctapres)
        {
            if(ctapres is CTAPResponseMakeCredential) {
                this.CTAPResponse = ctapres as CTAPResponseMakeCredential;
            } else {
                this.CTAPResponse = new CTAPResponseMakeCredential(ctapres);
            }
        }
    }

    public class ResponseReset : ResponseBase
    {
        public CTAPResponse CTAPResponse { get; private set; }
        public ResponseReset(DeviceStatus devst, CTAPResponse ctapres) : base(devst, ctapres) { this.CTAPResponse = ctapres; }
    }
}

