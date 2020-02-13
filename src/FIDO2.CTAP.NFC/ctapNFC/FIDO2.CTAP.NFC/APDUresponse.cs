using System;
using System.Linq;

namespace g.FIDO2.CTAP.NFC
{
    public class APDUresponse
    {
        public bool IsSuccess { get; private set; }
        public string Message { get; private set; }

        public byte[] Data { get; private set; }
        public byte Sw1 { get; private set; }
        public byte Sw2 { get; private set; }

        public APDUresponse(byte[] buff, int buffSize)
        {
            if (buffSize < 2) {
                // response error
                Sw1 = 0x00;
                Sw2 = 0x00;
                Data = null;
                IsSuccess = false;
                Message = "Response Size Error";
            } else {
                Data = new byte[buffSize - 2];
                Array.Copy(buff, Data, buffSize - 2);
                Sw1 = buff[buffSize - 2];
                Sw2 = buff[buffSize - 1];
                IsSuccess = APDUstatus.IsSuccess(Sw1, Sw2);
                Message = APDUstatus.GetMessage(Sw1, Sw2);
            }
        }

        public void Marge(APDUresponse add)
        {
            if( add.Data != null) {
                this.Data = Data.Concat(add.Data).ToArray();
            }
            this.Sw1 = add.Sw1;
            this.Sw2 = add.Sw2;
            this.IsSuccess = add.IsSuccess;
            this.Message = add.Message;
        }
    }
}
