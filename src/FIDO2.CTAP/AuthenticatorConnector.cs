using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP
{
    public abstract class AuthenticatorConnector
    {
        public enum DeviceStatus
        {
            Ok = 0,
            NotConnedted = 1,
            Timeout = 2,
            Unknown = 999,
        };

        public class ResponseBase
        {
            public DeviceStatus DeviceStatus { get; private set; }
            public ResponseBase(DeviceStatus devst) { this.DeviceStatus = devst; }
        }

        public class ResponseGetInfo: ResponseBase
        {
            public CTAPResponseGetInfo CTAPResponse { get; private set; }
            public ResponseGetInfo(DeviceStatus devst, CTAPResponse ctapres) : base(devst) { this.CTAPResponse = (CTAPResponseGetInfo)ctapres; }
        }

        /// <summary>
        /// CTAP-Command GetInfo
        /// </summary>
        public async Task<ResponseGetInfo> GetInfoAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandGetInfo(), new CTAPResponseGetInfo());
            return new ResponseGetInfo(DeviceStatus.Unknown, ret);
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getRetries
        /// </summary>
        public async Task<CTAPResponseClientPIN2_getRetries> ClientPINgetRetriesAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandClientPIN_getRetries(), new CTAPResponseClientPIN2_getRetries());
            return (CTAPResponseClientPIN2_getRetries)ret;
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getKeyAgreement
        /// </summary>
        public async Task<CTAPResponseClientPIN2_getKeyAgreement> ClientPINgetKeyAgreementAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandClientPIN_getKeyAgreement(), new CTAPResponseClientPIN2_getKeyAgreement());
            return (CTAPResponseClientPIN2_getKeyAgreement)ret;
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getPINToken use PIN string
        /// </summary>
        public async Task<CTAPResponseClientPIN2_getPINToken> ClientPINgetPINTokenAsync(string pin)
        {
            var ret = (CTAPResponseClientPIN2_getKeyAgreement)await sendCommandandResponseAsync(new CTAPCommandClientPIN_getKeyAgreement(), new CTAPResponseClientPIN2_getKeyAgreement());
            if (ret.Status != 0) {
                return new CTAPResponseClientPIN2_getPINToken(ret);
            }

            COSE_Key myKeyAgreement;
            var sharedSecret = CTAPCommandClientPIN.CreateSharedSecret(ret.KeyAgreement, out myKeyAgreement);

            var pinHashEnc = CTAPCommandClientPIN.CreatePinHashEnc(pin, sharedSecret);

            return await ClientPINgetPINTokenAsync(myKeyAgreement, pinHashEnc, sharedSecret);
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getPINToken
        /// </summary>
        public async Task<CTAPResponseClientPIN2_getPINToken> ClientPINgetPINTokenAsync(COSE_Key keyAgreement, byte[] pinHashEnc, byte[] sharedSecret)
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandClientPIN_getPINToken(keyAgreement, pinHashEnc), new CTAPResponseClientPIN2_getPINToken(sharedSecret));
            return (CTAPResponseClientPIN2_getPINToken)ret;
        }

        /// <summary>
        /// CTAP-Command ClientPIN - setPIN
        /// </summary>
        public async Task<CTAPResponseClientPIN> ClientPINsetPINAsync(string newpin)
        {
            var ret = (CTAPResponseClientPIN2_getKeyAgreement)await sendCommandandResponseAsync(new CTAPCommandClientPIN_getKeyAgreement(), new CTAPResponseClientPIN2_getKeyAgreement());
            if (ret.Status != 0) {
                return new CTAPResponseClientPIN2_getPINToken(ret);
            }

            COSE_Key myKeyAgreement;
            var sharedSecret = CTAPCommandClientPIN.CreateSharedSecret(ret.KeyAgreement, out myKeyAgreement);

            // pinAuth = LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
            var pinAuth = CTAPCommandClientPIN.CreatePinAuthforSetPin(sharedSecret, newpin);

            // newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
            byte[] newPinEnc = CTAPCommandClientPIN.CreateNewPinEnc(sharedSecret, newpin);

            var ret2 = await sendCommandandResponseAsync(new CTAPCommandClientPIN_setPIN(myKeyAgreement, pinAuth, newPinEnc), new CTAPResponseClientPIN());
            return (CTAPResponseClientPIN)ret2;
        }

        /// <summary>
        /// CTAP-Command ClientPIN - changePIN
        /// </summary>
        public async Task<CTAPResponseClientPIN> ClientPINchangePINAsync(string newpin, string currentpin)
        {
            var ret = (CTAPResponseClientPIN2_getKeyAgreement)await sendCommandandResponseAsync(new CTAPCommandClientPIN_getKeyAgreement(), new CTAPResponseClientPIN2_getKeyAgreement());
            if (ret.Status != 0) {
                return new CTAPResponseClientPIN2_getPINToken(ret);
            }

            COSE_Key myKeyAgreement;
            var sharedSecret = CTAPCommandClientPIN.CreateSharedSecret(ret.KeyAgreement, out myKeyAgreement);

            // pinAuth:
            //  LEFT(HMAC-SHA-256(sharedSecret, newPinEnc || pinHashEnc), 16).
            var pinAuth = CTAPCommandClientPIN.CreatePinAuthforChangePin(sharedSecret, newpin, currentpin);

            // newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
            byte[] newPinEnc = CTAPCommandClientPIN.CreateNewPinEnc(sharedSecret, newpin);

            // pinHashEnc:
            //  Encrypted first 16 bytes of SHA - 256 hash of curPin using sharedSecret: 
            //  AES256-CBC(sharedSecret, IV = 0, LEFT(SHA-256(curPin), 16)).
            var pinHashEnc = CTAPCommandClientPIN.CreatePinHashEnc(currentpin, sharedSecret);

            var ret2 = await sendCommandandResponseAsync(new CTAPCommandClientPIN_changePIN(myKeyAgreement, pinAuth,newPinEnc,pinHashEnc), new CTAPResponseClientPIN());
            return (CTAPResponseClientPIN)ret2;
        }

        /// <summary>
        /// CTAP-Command GetAssertion use pinAuth
        /// </summary>
        public async Task<CTAPResponseGetAssertion> GetAssertionAsync(CTAPCommandGetAssertionParam param, byte[] pinAuth = null)
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandGetAssertion(param, pinAuth), new CTAPResponseGetAssertion());
            return (CTAPResponseGetAssertion)ret;
        }

        /// <summary>
        /// CTAP-Command GetAssertion use PIN string
        /// </summary>
        public async Task<CTAPResponseGetAssertion> GetAssertionAsync(CTAPCommandGetAssertionParam param, string pin)
        {
            var token = await ClientPINgetPINTokenAsync(pin);
            if (token.Status != 0) {
                return new CTAPResponseGetAssertion(token);
            }

            var pinAuth = CTAPCommandClientPIN.CreatePinAuth(param.ClientDataHash, token.PinToken);

            var ret = await sendCommandandResponseAsync(new CTAPCommandGetAssertion(param, pinAuth), new CTAPResponseGetAssertion());
            return (CTAPResponseGetAssertion)ret;
        }

        /// <summary>
        /// CTAP-Command GetNextAssertion use pinAuth
        /// </summary>
        public async Task<CTAPResponseGetAssertion> GetNextAssertionAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandGetNextAssertion(), new CTAPResponseGetAssertion());
            return (CTAPResponseGetAssertion)ret;
        }

        /// <summary>
        /// CTAP-Command MakeCredential use pinAuth
        /// </summary>
        public async Task<CTAPResponseMakeCredential> MakeCredentialAsync(CTAPCommandMakeCredentialParam param, byte[] pinAuth = null)
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandMakeCredential(param, pinAuth), new CTAPResponseMakeCredential());
            return (CTAPResponseMakeCredential)ret;
        }

        /// <summary>
        /// CTAP-Command MakeCredential use PIN string
        /// </summary>
        public async Task<CTAPResponseMakeCredential> MakeCredentialAsync(CTAPCommandMakeCredentialParam param, string pin)
        {
            var token = await ClientPINgetPINTokenAsync(pin);
            if (token.Status != 0) {
                return new CTAPResponseMakeCredential(token);
            }

            var pinAuth = CTAPCommandClientPIN.CreatePinAuth(param.ClientDataHash, token.PinToken);

            var ret = await sendCommandandResponseAsync(new CTAPCommandMakeCredential(param, pinAuth), new CTAPResponseMakeCredential());
            return (CTAPResponseMakeCredential)ret;
        }

        internal abstract Task<CTAPResponse> sendCommandandResponseAsync(CTAPCommand cmd, CTAPResponse res);

        // PEND こっちに変更予定
        //internal abstract Task<(AuthenticatorConnector.DeviceStatus devSt, CTAPResponse ctapRes)> sendCommandandResponseAsync(CTAPCommand cmd, CTAPResponse res);

    }
}
