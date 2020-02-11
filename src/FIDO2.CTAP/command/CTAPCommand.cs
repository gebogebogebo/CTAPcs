using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.CTAP
{
    internal class CTAPCommand
    {
        public enum CTAPCommandType
        {
            authenticatorMakeCredential = 0x01,
            authenticatorGetAssertion = 0x02,
            authenticatorGetInfo = 0x04,
            authenticatorClientPIN = 0x06,
            authenticatorGetNextAssertion = 0x08,
        };

        public string PayloadJson { get; protected set; }

        protected static string getCommandName(CTAPCommandType commandType)
        {
            string name = "";
            switch (commandType) {
                case CTAPCommandType.authenticatorMakeCredential:
                    name = "authenticatorMakeCredential";
                    break;
                case CTAPCommandType.authenticatorGetAssertion:
                    name = "authenticatorGetAssertion";
                    break;
                case CTAPCommandType.authenticatorGetInfo:
                    name = "authenticatorGetInfo";
                    break;
                case CTAPCommandType.authenticatorClientPIN:
                    name = "authenticatorClientPIN";
                    break;
                case CTAPCommandType.authenticatorGetNextAssertion:
                    name = "authenticatorGetNextAssertion";
                    break;
            }
            return (name);
        }

        protected byte[]  create(CTAPCommandType commandType, CBORObject payload)
        {
            byte[] send = null;

            PayloadJson = string.Format($"[0x{(byte)commandType:X2}]({getCommandName(commandType)})");
            if (payload != null) {
                PayloadJson = PayloadJson + payload.ToJSONString();
                Logger.Log($"Send: {PayloadJson}");

                var payloadb = payload.EncodeToBytes();
                send = new byte[] { (byte)commandType }.Concat(payloadb).ToArray();
            } else {
                send = new byte[] { (byte)commandType };
            }
            return (send);
        }

        public virtual byte[] CreatePayload()
        {
            return null;
        }

    }

}
