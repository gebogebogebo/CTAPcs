using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Diagnostics;

namespace g.FIDO2.CTAP
{
    internal class ECDH
    {
        public static byte[] CreateSharedSecret(
                    byte[] aG_x,
                    byte[] aG_y,
                    out byte[] bG_x,
                    out byte[] bG_y
            )
        {
            string aG_x_str = BitConverter.ToString(aG_x).Replace("-", string.Empty);
            string aG_y_str = BitConverter.ToString(aG_y).Replace("-", string.Empty);
            bG_x = null;
            bG_y = null;

            Logger.Log($"CreateSharedSecretNew-START");
            Logger.Log($"in aG_x={aG_x_str}");
            Logger.Log($"in aG_y={aG_y_str}");

            // COSE ES256 (ECDSA over P-256 with SHA-256)
            // P-256
            ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng(256);

            {
                ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                // SHA-256
                ecdh.HashAlgorithm = CngAlgorithm.Sha256;
                var myPublicKey = ecdh.PublicKey.ToByteArray();

                if(myPublicKey.Length != 72) {
                    return null;
                }

                // delete head
                var pkey = myPublicKey.ToList().Skip(8).Take(64).ToList();

                // get
                bG_x = pkey.Take(32).ToArray();
                bG_y = pkey.Skip(32).Take(32).ToArray();
            }

            byte[] sharedSecret = null;
            {
                // CngKeyには追加の8バイトが含まれ、最初の4バイトは使用される曲線の
                // 名前（ECS1、ECS3、またはECS5）に使用され、
                // 最後の4バイトはキーinclの長さです。パディング（32、48、または66）
                // 証明書からの公開鍵の最初のバイトが削除されます（ECDSA公開鍵の場合は常に0x04です）。
                // たとえば、P-256曲線とSHA-256ハッシュアルゴリズムを使用したECDSAの場合、
                // 長さ65バイトの公開鍵が得られます。最初のバイトを破棄し、
                // 64バイトを残してから、カーブ用に4バイト、キー長用に4バイトを前に付けます。
                // すなわち、（Encoding.ASCII）：
                // - Ex.1 -
                // 69(E)            0x45
                // 67(C)            0x43
                // 83(S)            0x53
                // 49(1)            0x31
                // 32(Key length)   0x20
                // 0
                // 0
                // 0
                //これでCngKeyを作成するための公開鍵（72バイト）が手に入りました。
                // 
                // - Ex.2 -
                // 69(E)            0x45
                // 67(C)            0x43
                // 75(K)            0x4B
                // 49(1)            0x31
                // 32(Key length)   0x20
                // 0
                // 0
                // 0

                // 64byte
                string aGpublicKey = aG_x_str + aG_y_str;
                // 8+64=72byte
                //string publicKeyforChgKey = "4543533120000000" + aGpublicKey;
                string publicKeyforChgKey = "45434B3120000000" + aGpublicKey;
                var array = Common.HexStringToBytes(publicKeyforChgKey);

                CngKey.Import(array, CngKeyBlobFormat.EccPublicBlob);

                // 32byte
                sharedSecret = ecdh.DeriveKeyMaterial(CngKey.Import(array, CngKeyBlobFormat.EccPublicBlob));
                if(sharedSecret.Length != 32) {
                    return null;
                }
            }

            Logger.Log($"out bG_x={Common.BytesToHexString(bG_x)}");
            Logger.Log($"out bG_y={Common.BytesToHexString(bG_y)}");
            Logger.Log($"out sharedSecret={Common.BytesToHexString(sharedSecret)}");
            Logger.Log($"CreateSharedSecretNew-END");

            return sharedSecret;
        }

    }
}
