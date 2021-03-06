﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP.BLE
{
    internal class BLEResponsePacket
    {
        public byte Constant { get; private set; } = 0x00;
        private int needSize = 0;
        private List<byte> cborbyte;

        public BLEResponsePacket()
        {
            cborbyte = new List<byte>();
        }

        public BLEResponsePacket(byte[] data)
        {
            cborbyte = new List<byte>();

            // constant(MSG=0x83,ERROR=0xbf)
            Constant = data[0];

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
            //// The first 1 byte is the response status from 2 bytes to CBOR data
            var tmp = buff.Take(buff.Length).ToArray();
            // 受信バッファに追加 | Add to receive buffer
            cborbyte.AddRange(tmp.ToList());
        }

        public void Add(byte[] data)
        {
            // 最初の1byteは応答ステータスで2byteからCBORデータ
            // The first 1 byte is the response status from 2 bytes to CBOR data
            var tmp = data.Skip(1).Take(data.Length).ToArray();

            // 受信バッファに追加 | Add to receive buffer
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
            this.Constant = 0x00;
            this.needSize = 0;
            cborbyte = new List<byte>();
        }
    }
}
