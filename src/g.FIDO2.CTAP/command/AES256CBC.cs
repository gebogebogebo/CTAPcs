using System.Security.Cryptography;

namespace g.FIDO2.CTAP
{
    internal static class AES256CBC
    {
        public static byte[] Encrypt(byte[] key, byte[] data)
        {
            // 暗号化方式はAES | Encryption method is AES
            using (AesManaged aes = new AesManaged())
            {
                // 鍵の長さ | Key length
                aes.KeySize = 256;
                // ブロックサイズ（何文字単位で処理するか）| Block size (how many characters to process)
                aes.BlockSize = 128;
                // 暗号利用モード | Cipher mode of operation
                aes.Mode = CipherMode.CBC;
                // 初期化ベクトル(0x00×16byte) | Initialization vector (0x00 × 16byte)
                aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                aes.Key = key;
                // パディング | Padding
                aes.Padding = PaddingMode.None;

                // 暗号化 | encryption
                var encdata = aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);

                return (encdata);
            }
        }

        public static byte[] Decrypt(byte[] key, byte[] data)
        {
            // 暗号化方式はAES Encryption method is AES
            using (AesManaged aes = new AesManaged())
            {
                // 鍵の長さ| Key length
                aes.KeySize = 256;
                // ブロックサイズ（何文字単位で処理するか）| Block size (how many characters to process
                aes.BlockSize = 128;
                // 暗号利用モード | Cipher mode of operation
                aes.Mode = CipherMode.CBC;
                // 初期化ベクトル(0x00×16byte) | Initialization vector (0x00 × 16byte)
                aes.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                aes.Key = key;
                // パディング | Padding
                aes.Padding = PaddingMode.None;

                var encdata = aes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);

                return (encdata);
            }
        }
    }
}
