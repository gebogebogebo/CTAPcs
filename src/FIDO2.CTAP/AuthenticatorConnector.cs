using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP
{
    public abstract class AuthenticatorConnector
    {
        /// <summary>
        /// CTAP-Command GetInfo
        /// </summary>
        public async Task<ResponseGetInfo> GetInfoAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandGetInfo(), new CTAPResponseGetInfo());
            return new ResponseGetInfo(ret.devSt, ret.ctapRes);
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getRetries
        /// </summary>
        public async Task<ResponseClientPIN_getRetries> ClientPINgetRetriesAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandClientPIN_getRetries(), new CTAPResponseClientPIN_getRetries());
            return new ResponseClientPIN_getRetries(ret.devSt, ret.ctapRes);
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getKeyAgreement
        /// </summary>
        public async Task<ResponseClientPIN_getKeyAgreement> ClientPINgetKeyAgreementAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandClientPIN_getKeyAgreement(), new CTAPResponseClientPIN2_getKeyAgreement());
            return new ResponseClientPIN_getKeyAgreement(ret.devSt, ret.ctapRes);
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getPINToken use PIN string
        /// </summary>
        public async Task<ResponseClientPIN_getPINToken> ClientPINgetPINTokenAsync(string pin)
        {
            var ret = await ClientPINgetKeyAgreementAsync();
            if (ret.DeviceStatus != DeviceStatus.Ok || ret.CTAPResponse==null || ret.CTAPResponse.Status != 0) {
                return new ResponseClientPIN_getPINToken(ret.DeviceStatus,ret.CTAPResponse);
            }

            COSE_Key myKeyAgreement;
            var sharedSecret = CTAPCommandClientPIN.CreateSharedSecret(ret.CTAPResponse.KeyAgreement, out myKeyAgreement);

            var pinHashEnc = CTAPCommandClientPIN.CreatePinHashEnc(pin, sharedSecret);

            return await ClientPINgetPINTokenAsync(myKeyAgreement, pinHashEnc, sharedSecret);
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getPINToken
        /// </summary>
        public async Task<ResponseClientPIN_getPINToken> ClientPINgetPINTokenAsync(COSE_Key keyAgreement, byte[] pinHashEnc, byte[] sharedSecret)
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandClientPIN_getPINToken(keyAgreement, pinHashEnc), new CTAPResponseClientPIN_getPINToken(sharedSecret));
            return new ResponseClientPIN_getPINToken(ret.devSt, ret.ctapRes);
        }

        /// <summary>
        /// CTAP-Command ClientPIN - setPIN
        /// </summary>
        public async Task<ResponseClientPIN> ClientPINsetPINAsync(string newpin)
        {
            var ret = await ClientPINgetKeyAgreementAsync();
            if (ret.DeviceStatus != DeviceStatus.Ok || ret.CTAPResponse == null || ret.CTAPResponse.Status != 0) {
                return new ResponseClientPIN(ret.DeviceStatus,ret.CTAPResponse);
            }

            COSE_Key myKeyAgreement;
            var sharedSecret = CTAPCommandClientPIN.CreateSharedSecret(ret.CTAPResponse.KeyAgreement, out myKeyAgreement);

            // pinAuth = LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
            var pinAuth = CTAPCommandClientPIN.CreatePinAuthforSetPin(sharedSecret, newpin);

            // newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
            byte[] newPinEnc = CTAPCommandClientPIN.CreateNewPinEnc(sharedSecret, newpin);

            var ret2 = await sendCommandandResponseAsync(new CTAPCommandClientPIN_setPIN(myKeyAgreement, pinAuth, newPinEnc), new CTAPResponseClientPIN());
            return new ResponseClientPIN(ret2.devSt, ret2.ctapRes);
        }

        /// <summary>
        /// CTAP-Command ClientPIN - changePIN
        /// </summary>
        public async Task<ResponseClientPIN> ClientPINchangePINAsync(string newpin, string currentpin)
        {
            var ret = await ClientPINgetKeyAgreementAsync();
            if (ret.DeviceStatus != DeviceStatus.Ok || ret.CTAPResponse == null || ret.CTAPResponse.Status != 0) {
                return new ResponseClientPIN(ret.DeviceStatus,ret.CTAPResponse);
            }

            COSE_Key myKeyAgreement;
            var sharedSecret = CTAPCommandClientPIN.CreateSharedSecret(ret.CTAPResponse.KeyAgreement, out myKeyAgreement);

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
            return new ResponseClientPIN(ret2.devSt,ret2.ctapRes);
        }

        /// <summary>
        /// CTAP-Command GetAssertion use pinAuth
        /// </summary>
        public async Task<ResponseGetAssertion> GetAssertionAsync(CTAPCommandGetAssertionParam param, byte[] pinAuth = null)
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandGetAssertion(param, pinAuth), new CTAPResponseGetAssertion());
            return new ResponseGetAssertion(ret.devSt,ret.ctapRes);
        }

        /// <summary>
        /// CTAP-Command GetAssertion use PIN string
        /// </summary>
        public async Task<ResponseGetAssertion> GetAssertionAsync(CTAPCommandGetAssertionParam param, string pin)
        {
            var token = await ClientPINgetPINTokenAsync(pin);
            if (token.DeviceStatus != DeviceStatus.Ok || token.CTAPResponse == null || token.CTAPResponse.Status != 0) {
                return new ResponseGetAssertion(token.DeviceStatus,token.CTAPResponse);
            }

            var pinAuth = CTAPCommandClientPIN.CreatePinAuth(param.ClientDataHash, token.CTAPResponse.PinToken);

            var ret = await sendCommandandResponseAsync(new CTAPCommandGetAssertion(param, pinAuth), new CTAPResponseGetAssertion());
            return new ResponseGetAssertion(ret.devSt,ret.ctapRes);
        }

        /// <summary>
        /// CTAP-Command GetNextAssertion use pinAuth
        /// </summary>
        public async Task<ResponseGetAssertion> GetNextAssertionAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandGetNextAssertion(), new CTAPResponseGetAssertion());
            return new ResponseGetAssertion(ret.devSt, ret.ctapRes);
        }

        /// <summary>
        /// CTAP-Command MakeCredential use pinAuth
        /// </summary>
        public async Task<ResponseMakeCredential> MakeCredentialAsync(CTAPCommandMakeCredentialParam param, byte[] pinAuth = null)
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandMakeCredential(param, pinAuth), new CTAPResponseMakeCredential());
            return new ResponseMakeCredential(ret.devSt, ret.ctapRes);
        }

        /// <summary>
        /// CTAP-Command MakeCredential use PIN string
        /// </summary>
        public async Task<ResponseMakeCredential> MakeCredentialAsync(CTAPCommandMakeCredentialParam param, string pin)
        {
            var token = await ClientPINgetPINTokenAsync(pin);
            if (token.DeviceStatus != DeviceStatus.Ok || token.CTAPResponse == null || token.CTAPResponse.Status != 0) {
                return new ResponseMakeCredential(token.DeviceStatus,token.CTAPResponse);
            }

            var pinAuth = CTAPCommandClientPIN.CreatePinAuth(param.ClientDataHash, token.CTAPResponse.PinToken);

            var ret = await sendCommandandResponseAsync(new CTAPCommandMakeCredential(param, pinAuth), new CTAPResponseMakeCredential());
            return new ResponseMakeCredential(ret.devSt, ret.ctapRes);
        }

        /// <summary>
        /// CTAP-Command Reset
        /// </summary>
        public async Task<ResponseReset> ResetAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandReset(), new CTAPResponse());
            return new ResponseReset(ret.devSt, ret.ctapRes);
        }

        internal abstract Task<(DeviceStatus devSt, CTAPResponse ctapRes)> sendCommandandResponseAsync(CTAPCommand cmd, CTAPResponse res);
    }
}
