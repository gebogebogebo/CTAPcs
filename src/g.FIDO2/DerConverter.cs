using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace g.FIDO2
{
    public class DerConverter
    {
        // Private Key
        public static string ToPemRSAPrivateKey(byte[] der)
        {
            var pemdata = "-----BEGIN RSA PRIVATE KEY-----\n" + toPem(der) + "-----END RSA PRIVATE KEY-----";
            return pemdata;
        }

        // Publick Key
        public static string ToPemPublicKey(byte[] der)
        {
            var pemdata = string.Format("-----BEGIN PUBLIC KEY-----\n") + toPem(der) + string.Format("-----END PUBLIC KEY-----");
            return pemdata;
        }

        // Certificate
        public static string ToPemCertificate(byte[] der)
        {
            var pemdata = string.Format("-----BEGIN CERTIFICATE-----\n") + toPem(der) + string.Format("-----END CERTIFICATE-----");
            return pemdata;
        }

        private static string toPem(byte[] der)
        {
            // DER形式をPEM形式に変換する
            //     DER -> 鍵や証明書をASN.1というデータ構造で表し、それをシリアライズしたバイナリファイル
            //     PEM -> DERと同じASN.1のバイナリデータをBase64によってテキスト化されたファイル 
            // 1.Base64エンコード
            // 2.64文字ごとに改行コードをいれる
            // 3.ヘッダとフッタを入れる

            var b64cert = Convert.ToBase64String(der);

            string pemdata = "";
            int roopcount = (int)Math.Ceiling(b64cert.Length / 64.0f);
            for (int intIc = 0; intIc < roopcount; intIc++) {
                int start = 64 * intIc;
                if (intIc == roopcount - 1) {
                    pemdata = pemdata + b64cert.Substring(start) + "\n";
                } else {
                    pemdata = pemdata + b64cert.Substring(start, 64) + "\n";
                }
            }
            return pemdata;
        }

    }
}
