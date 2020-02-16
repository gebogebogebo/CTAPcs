using System;
using System.Collections.Generic;
using System.Linq;

namespace g.FIDO2.CTAP.NFC
{
    public class ICReader : IDisposable
    {
        public string LinkedReaderName { get; private set; }

        private IntPtr context = IntPtr.Zero;
        private IntPtr handle = IntPtr.Zero;
        private byte[] recvBuff;
        private List<string> targetReaderNames=new List<string>();

        /*
        public ICReader()
        {
            create();
        }
        */
        public ICReader(string targetReaderName)
        {
            create();
            this.targetReaderNames.Add(targetReaderName);
        }

        public ICReader(List<string> targetReaderNames)
        {
            create();
            this.targetReaderNames = targetReaderNames;
        }

        private bool create()
        {
            SCardResult result = SCardAPI.SCardEstablishContext(SCardAPI.SCARD_SCOPE_USER, IntPtr.Zero, IntPtr.Zero, out this.context);
            if (result != SCardResult.SCARD_S_SUCCESS) {
                this.context = IntPtr.Zero;
                return false;
            }
            return true;
        }

        private static void logResponse(byte[] addu, APDUresponse res)
        {
            /*
            logger.Debug(string.Format($"SendAPDU={CTAP2.Common.BytesToHexString(addu)}"));
            logger.Debug(string.Format($"IsSuccess={res.IsSuccess}"));
            logger.Debug(string.Format($"Message={res.Message}"));
            logger.Debug(string.Format($"SW1=0x{res.Sw1:X2},SW2=0x{res.Sw2:X2}"));
            logger.Debug(string.Format($"Data={CTAP2.Common.BytesToHexString(res.Data)}"));
            */
        }

        public void Dispose()
        {
            Disconnect();
            if (this.context != IntPtr.Zero) {
                SCardAPI.SCardReleaseContext(this.context);
                this.context = IntPtr.Zero;
                this.LinkedReaderName = "";
            }
        }

        public bool Connect()
        {
            bool ret = false;
            try {
                if(isLinkedReader() == false ) {
                    return false;
                }

                uint protocol;
                var result = SCardAPI.SCardConnect(this.context, this.LinkedReaderName, SCardAPI.SCARD_SHARE_SHARED, SCardAPI.SCARD_PROTOCOL_T1, out handle, out protocol);
                if (result != SCardResult.SCARD_S_SUCCESS) {
                    throw (new Exception("SCardConnect"));
                }

                this.recvBuff = new byte[1024];

                ret = true;
            } catch (Exception) {
                this.LinkedReaderName = "";
            }
            return ret;
        }

        protected bool Disconnect()
        {
            if (this.handle != IntPtr.Zero) {
                var result = SCardAPI.SCardDisconnect(this.handle, SCardAPI.SCARD_LEAVE_CARD);
                if (result == SCardResult.SCARD_S_SUCCESS) {
                    this.handle = IntPtr.Zero;
                    this.recvBuff = null;
                    this.LinkedReaderName = "";
                    return true;
                }
            }
            return false;
        }

        public APDUresponse SendandResponse(byte[] apdu)
        {
            APDUresponse res = null;
            try {
                int recvSize = SCardAPI.SCardTransmit(this.handle, apdu, this.recvBuff);
                res = new APDUresponse(recvBuff, recvSize);
            } catch (Exception) {
            } finally {
                logResponse(apdu, res);
            }
            return res;
        }

        public byte[] GetATR()
        {
            var resultAtr = new List<byte>();

            try {
                uint atrLen=33;
                byte[] atr = new byte[33];

                uint pcchReaderLen = 0; ;
                uint pdwState = 0;
                uint pdwProtocol = 0;

                var result = SCardAPI.SCardStatus(this.handle,
                                            null, ref pcchReaderLen,
                                            out pdwState, out pdwProtocol,
                                            atr, ref atrLen);

                if (result != SCardResult.SCARD_S_SUCCESS) {
                    return null;
                }

                for (int index = 0; index < atrLen; index++) {
                    resultAtr.Add(atr[index]);
                }

            } catch (Exception) {
            }
            return resultAtr.ToArray();
        }

        public string GetLinkedReaderName()
        {
            if( isLinkedReader() == true ) {
                return(this.LinkedReaderName);
            } else {
                return ("");
            }
        }

        public bool isLinkedReader()
        {
            bool ret = false;
            try {
                if( this.context == IntPtr.Zero) {
                    return false;
                }

                // get size
                uint readerSize = 0;
                var result = SCardAPI.SCardListReaders(this.context, null, null, ref readerSize);
                if (result != SCardResult.SCARD_S_SUCCESS) {
                    throw (new Exception("SCardListReaders"));
                }

                // get readerData
                char[] readerData = new char[readerSize];
                result = SCardAPI.SCardListReaders(this.context, null, readerData, ref readerSize);
                if (result != SCardResult.SCARD_S_SUCCESS) {
                    throw (new Exception("SCardListReaders"));
                }

                // リーダー・ライターの名称分割(\u0000で区切られている)
                string[] readers = getNames(readerData);
                if( readers.Count() <= 0) {
                    throw (new Exception("getNames"));
                }

                // select target
                bool find = false;
                {
                    if(targetReaderNames.Count <= 0) {
                        this.LinkedReaderName = readers[0];
                        find = true;
                    } else {
                        foreach (string readerName in readers) {
                            foreach( string target in targetReaderNames) {
                                if (readerName.StartsWith(target, StringComparison.OrdinalIgnoreCase)) {
                                    this.LinkedReaderName = readerName;
                                    find = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                ret = find;

            } catch (Exception) {
            }
            return (ret);
        }

        private static string[] getNames(char[] source)
        {
            if (source == null) {
                return new string[0];
            } else {
                string create = new String(source);
                List<string> result = new List<string>();
                foreach (string element in create.Split('\u0000')) {
                    if (!String.IsNullOrEmpty(element)) {
                        result.Add(element);
                    }
                }
                return result.ToArray();
            }
        }

    }
}
