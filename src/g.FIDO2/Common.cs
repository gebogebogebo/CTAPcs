using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace g.FIDO2
{
    public static class Common
    {
        // 16進数文字列 => Byte配列
        public static byte[] HexStringToBytes(string str)
        {
            var bs = new List<byte>();
            for (int i = 0; i < str.Length / 2; i++) {
                bs.Add(Convert.ToByte(str.Substring(i * 2, 2), 16));
            }
            // "01-AB-EF" こういう"-"区切りを想定する場合は以下のようにする
            // var bs = str.Split('-').Select(hex => Convert.ToByte(hex, 16));
            return bs.ToArray();
        }

        // Byte配列 => 16進数文字列
        public static string BytesToHexString(byte[] bs)
        {
            if (bs == null) return "";
            var str = BitConverter.ToString(bs);
            // "-"がいらないなら消しておく
            str = str.Replace("-", string.Empty);
            return str;
        }

        public static string ToHexString(this byte[] bs)
        {
            return BytesToHexString(bs);
        }

        public static int ToInt32(byte[] value, int startIndex, bool changeEndian = false)
        {
            byte[] sub = GetSubArray(value, startIndex, 4);
            if (changeEndian == true) {
                sub = sub.Reverse().ToArray();
            }
            return BitConverter.ToInt32(sub, 0);
        }

        public static int ToInt16(byte[] value, int startIndex, bool changeEndian = false)
        {
            byte[] sub = GetSubArray(value, startIndex, 2);
            if (changeEndian == true) {
                sub = sub.Reverse().ToArray();
            }
            return BitConverter.ToInt16(sub, 0);
        }

        public static int ToUInt16(byte[] value, int startIndex, bool changeEndian = false)
        {
            byte[] sub = GetSubArray(value, startIndex, 2);
            if (changeEndian == true) {
                sub = sub.Reverse().ToArray();
            }
            return BitConverter.ToUInt16(sub, 0);
        }

        // バイト配列から一部分を抜き出す
        private static byte[] GetSubArray(byte[] src, int startIndex, int count)
        {
            byte[] dst = new byte[count];
            Array.Copy(src, startIndex, dst, 0, count);
            return dst;
        }

        public static bool GetBit(byte bdata,int bit)
        {
            byte mask = 0x00;
            if( bit == 0) {
                mask = 0x01;
            } else if( bit == 1) {
                mask = 0x02;
            } else if (bit == 2) {
                mask = 0x04;
            } else if (bit == 3) {
                mask = 0x08;
            } else if (bit == 4) {
                mask = 0x10;
            } else if (bit == 5) {
                mask = 0x20;
            } else if (bit == 6) {
                mask = 0x40;
            } else if (bit == 7) {
                mask = 0x80;
            }
            if ((bdata & mask) == mask) {
                return true;
            } else {
                return false;
            }
        }

        public static byte SetBit(byte bdata, int bitno, bool bitval)
        {
            int mask = 1 << bitno;
            var ret = bitval ? bdata | mask : bdata & ~mask;
            return (byte)ret;
        }

        public static List<byte[]> Chunk(byte[] data, int chunkSize)
        {
            var ret = new List<byte[]>();

            var chunks = data.Select((v, i) => new { v, i })
                .GroupBy(x => x.i / chunkSize)
                .Select(g => g.Select(x => x.v));

            foreach (var chunk in chunks) {
                ret.Add(chunk.ToArray());
            }
            return ret;
        }

        static public bool IsAdministrator()
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        static public byte[] CreateClientDataHash(string challenge)
        {
            byte[] input = System.Text.Encoding.ASCII.GetBytes(challenge);
            return (CreateClientDataHash(input));
        }

        static public byte[] CreateClientDataHash(byte[] challenge)
        {
            SHA256 sha = new SHA256CryptoServiceProvider();
            var cdh = sha.ComputeHash(challenge);
            return (cdh);
        }

    }
}

