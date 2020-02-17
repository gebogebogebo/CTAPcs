using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP.BLE
{
    internal class BLEResponsePacket
    {
        private int needSize = 0;
        private List<byte> cborbyte;

        public BLEResponsePacket()
        {
            cborbyte = new List<byte>();
        }

        public BLEResponsePacket(byte[] data)
        {
            cborbyte = new List<byte>();

            // [1] HLEN
            // [2] LLEN
            {
                var len = new byte[2];
                len[0] = data[2];
                len[1] = data[1];

                needSize = BitConverter.ToInt16(len, 0);
            }

            // [3-] DATA
            var buff = data.Skip(3).Take(data.Length).ToArray();
            // 最初の1byteは応答ステータスで2byteからCBORデータ
            var tmp = buff.Take(buff.Length).ToArray();
            // 受信バッファに追加
            cborbyte.AddRange(tmp.ToList());
        }

        public void Add(byte[] data)
        {
            // 最初の1byteは応答ステータスで2byteからCBORデータ
            var tmp = data.Skip(1).Take(data.Length).ToArray();
            // 受信バッファに追加
            cborbyte.AddRange(tmp.ToList());
        }

        public bool IsReceiveComplete()
        {
            if (needSize <= 0 || cborbyte.Count <= 0) {
                return false;
            }
            if (cborbyte.Count == needSize) {
                return true;
            } else {
                return false;
            }
        }

        public byte[] Get()
        {
            return (this.cborbyte.ToArray());
        }

        public void Clear()
        {
            this.needSize = 0;
            cborbyte = new List<byte>();
        }
    }
}
