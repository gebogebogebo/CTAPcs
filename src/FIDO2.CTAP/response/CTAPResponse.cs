using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.CTAP
{
    public class CTAPResponse
    {
        public byte Status { get; private set; }
        public string StatusMsg { get; private set; }
        public string ResponsePayloadJson { get; private set; }
        public string SendPayloadJson { get; set; }

        public CTAPResponse(CTAPResponse obj)
        {
            Status = obj.Status;
            StatusMsg = obj.StatusMsg;
            ResponsePayloadJson = obj.ResponsePayloadJson;
            SendPayloadJson = obj.SendPayloadJson;
        }

        public CTAPResponse()
        {
            Status = 0;
            ResponsePayloadJson = "";
        }

        protected CBORObject decodeFromBytes(byte[] byteresponse)
        {
            CBORObject cbor=null;

            // Status
            Status = byteresponse[0];
            StatusMsg = CTAPResponse.GetMessage(Status);

            if (byteresponse.Length > 1) {
                try {
                    // CBOR 
                    var cobrbyte = byteresponse.Skip(1).ToArray();
                    cbor = CBORObject.DecodeFromBytes(cobrbyte, CBOREncodeOptions.Default);

                    ResponsePayloadJson = cbor.ToJSONString();
                    Logger.Log($"Recv: {ResponsePayloadJson}");
                } catch (Exception ex) {
                    Logger.Log($"CBOR DecordError:{ex.Message}");
                }
            }

            return cbor;
        }

        public virtual void Parse(byte[] byteresponse) { }

        protected CBORObject getObj(CBORObject cbor, byte findKey)
        {
            foreach (var key in cbor.Keys) {
                var keyVal = key.AsByte();
                if (keyVal == findKey) {
                    return cbor[key];
                }
            }
            return null;
        }

        protected bool getKeyValueAsBool(CBORObject obj, string key)
        {
            if (obj.ContainsKey(key)) {
                return (obj[key].AsBoolean());
            } else {
                return false;
            }
        }

        protected bool? getKeyValueAsBoolorNull(CBORObject obj, string key)
        {
            if (obj.ContainsKey(key)) {
                return (obj[key].AsBoolean());
            } else {
                return null;
            }
        }

        protected string[] getKeyValueAsStringArray(CBORObject obj)
        {
            var tmp = new List<string>();
            obj.Values.ToList().ForEach(x => tmp.Add(x.AsString()));
            return (tmp.ToArray());
        }

        protected int[] getKeyValueAsIntArray(CBORObject obj)
        {
            var tmp = new List<int>();
            obj.Values.ToList().ForEach(x => tmp.Add(x.AsInt32()));
            return (tmp.ToArray());
        }

        static public string GetMessage(byte status)
        {
            string msg = "";
            switch (status) {
                case 0x00: msg = "0x00 CTAP1_ERR_SUCCESS Indicates successful response."; break;
                case 0x01: msg = "0x01 CTAP1_ERR_INVALID_COMMAND The command is not a valid CTAP command."; break;
                case 0x02: msg = "0x02 CTAP1_ERR_INVALID_PARAMETER The command included an invalid parameter."; break;
                case 0x03: msg = "0x03 CTAP1_ERR_INVALID_LENGTH Invalid message or item length."; break;
                case 0x04: msg = "0x04 CTAP1_ERR_INVALID_SEQ Invalid message sequencing."; break;
                case 0x05: msg = "0x05 CTAP1_ERR_TIMEOUT Message timed out."; break;
                case 0x06: msg = "0x06 CTAP1_ERR_CHANNEL_BUSY Channel busy."; break;
                case 0x0A: msg = "0x0A CTAP1_ERR_LOCK_REQUIRED Command requires channel lock."; break;
                case 0x0B: msg = "0x0B CTAP1_ERR_INVALID_CHANNEL Command not allowed on this cid."; break;
                case 0x11: msg = "0x11 CTAP2_ERR_CBOR_UNEXPECTED_TYPE Invalid/ unexpected CBOR error."; break;
                case 0x12: msg = "0x12 CTAP2_ERR_INVALID_CBOR Error when parsing CBOR."; break;
                case 0x14: msg = "0x14 CTAP2_ERR_MISSING_PARAMETER Missing non - optional parameter."; break;
                case 0x15: msg = "0x15 CTAP2_ERR_LIMIT_EXCEEDED Limit for number of items exceeded."; break;
                case 0x16: msg = "0x16 CTAP2_ERR_UNSUPPORTED_EXTENSION Unsupported extension."; break;
                case 0x19: msg = "0x19 CTAP2_ERR_CREDENTIAL_EXCLUDED   Valid credential found in the exclude list."; break;
                case 0x21: msg = "0x21 CTAP2_ERR_PROCESSING    Processing(Lengthy operation is in progress)."; break;
                case 0x22: msg = "0x22 CTAP2_ERR_INVALID_CREDENTIAL    Credential not valid for the authenticator."; break;
                case 0x23: msg = "0x23 CTAP2_ERR_USER_ACTION_PENDING   Authentication is waiting for user interaction."; break;
                case 0x24: msg = "0x24 CTAP2_ERR_OPERATION_PENDING Processing, lengthy operation is in progress."; break;
                case 0x25: msg = "0x25 CTAP2_ERR_NO_OPERATIONS No request is pending."; break;
                case 0x26: msg = "0x26 CTAP2_ERR_UNSUPPORTED_ALGORITHM Authenticator does not support requested algorithm."; break;
                case 0x27: msg = "0x27 CTAP2_ERR_OPERATION_DENIED  Not authorized for requested operation."; break;
                case 0x28: msg = "0x28 CTAP2_ERR_KEY_STORE_FULL    Internal key storage is full."; break;
                case 0x29: msg = "0x29 CTAP2_ERR_NOT_BUSY  Authenticator cannot cancel as it is not busy."; break;
                case 0x2A: msg = "0x2A CTAP2_ERR_NO_OPERATION_PENDING No outstanding operations."; break;
                case 0x2B: msg = "0x2B CTAP2_ERR_UNSUPPORTED_OPTION Unsupported option."; break;
                case 0x2C: msg = "0x2C CTAP2_ERR_INVALID_OPTION Not a valid option for current operation."; break;
                case 0x2D: msg = "0x2D CTAP2_ERR_KEEPALIVE_CANCEL  Pending keep alive was cancelled."; break;
                case 0x2E: msg = "0x2E CTAP2_ERR_NO_CREDENTIALS    No valid credentials provided."; break;
                case 0x2F: msg = "0x2F CTAP2_ERR_USER_ACTION_TIMEOUT   Timeout waiting for user interaction."; break;
                case 0x30: msg = "0x30 CTAP2_ERR_NOT_ALLOWED   Continuation command, such as, authenticatorGetNextAssertion not allowed."; break;
                case 0x31: msg = "0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid."; break;
                case 0x32: msg = "0x32 CTAP2_ERR_PIN_BLOCKED PIN Blocked."; break;
                case 0x33: msg = "0x33 CTAP2_ERR_PIN_AUTH_INVALID PIN authentication, pinAuth, verification failed."; break;
                case 0x34: msg = "0x34 CTAP2_ERR_PIN_AUTH_BLOCKED PIN authentication, pinAuth, blocked.Requires power recycle to reset."; break;
                case 0x35: msg = "0x35 CTAP2_ERR_PIN_NOT_SET No PIN has been set."; break;
                case 0x36: msg = "0x36 CTAP2_ERR_PIN_REQUIRED  PIN is required for the selected operation."; break;
                case 0x37: msg = "0x37 CTAP2_ERR_PIN_POLICY_VIOLATION  PIN policy violation.Currently only enforces minimum length."; break;
                case 0x38: msg = "0x38 CTAP2_ERR_PIN_TOKEN_EXPIRED pinToken expired on authenticator."; break;
                case 0x39: msg = "0x39 CTAP2_ERR_REQUEST_TOO_LARGE Authenticator cannot handle this request due to memory constraints."; break;
                case 0x3A: msg = "0x3A CTAP2_ERR_ACTION_TIMEOUT The current operation has timed out."; break;
                case 0x3B: msg = "0x3B CTAP2_ERR_UP_REQUIRED User presence is required for the requested operation."; break;
                case 0x7F: msg = "0x7F CTAP1_ERR_OTHER Other unspecified error."; break;
                case 0xDF: msg = "0xDF CTAP2_ERR_SPEC_LAST CTAP 2 spec last error."; break;
                case 0xE0: msg = "0xE0 CTAP2_ERR_EXTENSION_FIRST Extension specific error."; break;
                case 0xEF: msg = "0xEF CTAP2_ERR_EXTENSION_LAST Extension specific error."; break;
                case 0xF0: msg = "0xF0 CTAP2_ERR_VENDOR_FIRST Vendor specific error."; break;
                case 0xff: msg = "0xFF CTAP2_ERR_VENDOR_LAST   Vendor specific error."; break;
                // CTAP仕様にない、謎のステータス
                case 0x6A: msg = "0x6A BioPass UnKnown Error."; break;
            }
            return (msg);
        }

    }
}
