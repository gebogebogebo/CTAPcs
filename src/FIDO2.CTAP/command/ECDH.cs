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
        public static int CreateSharedSecret(
                    string aG_x, string aG_y,               // (I )64文字
                    StringBuilder bG_x, StringBuilder bG_y, // ( O)64文字
                    StringBuilder sharedSecret              // ( O)64文字
            )
        {
            Logger.Log($"CreateSharedSecretNew-START");
            Logger.Log($"in aG_x={aG_x}");
            Logger.Log($"in aG_y={aG_y}");

            // COSE ES256 (ECDSA over P-256 with SHA-256)
            // P-256
            ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng(256);

            {
                ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                // SHA-256
                ecdh.HashAlgorithm = CngAlgorithm.Sha256;
                var myPublicKey = ecdh.PublicKey.ToByteArray();

                if(myPublicKey.Length != 72) {
                    return -1;
                }

                // delete head
                var pkey = myPublicKey.ToList().Skip(8).Take(64).ToList();
                var pkeyx = pkey.Take(32);
                var pkeyy = pkey.Skip(32).Take(32);

                bG_x.Append(Common.BytesToHexString(pkeyx.ToArray()));
                bG_y.Append(Common.BytesToHexString(pkeyy.ToArray()));
            }

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
                string aGpublicKey = aG_x + aG_y;
                // 8+64=72byte
                //string publicKeyforChgKey = "4543533120000000" + aGpublicKey;
                string publicKeyforChgKey = "45434B3120000000" + aGpublicKey;
                var array = Common.HexStringToBytes(publicKeyforChgKey);

                CngKey.Import(array, CngKeyBlobFormat.EccPublicBlob);

                // 32byte
                byte[] key = ecdh.DeriveKeyMaterial(CngKey.Import(array, CngKeyBlobFormat.EccPublicBlob));
                if( key.Length != 32) {
                    return -2;
                }
                sharedSecret.Append(Common.BytesToHexString(key));
            }

            Logger.Log($"out bG_x={bG_x}");
            Logger.Log($"out bG_y={bG_y}");
            Logger.Log($"out sharedSecret={sharedSecret}");
            Logger.Log($"CreateSharedSecretNew-END");

            return 0;
        }

    }
}
