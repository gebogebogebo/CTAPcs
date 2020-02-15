using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace g.FIDO2.Util
{
    internal class CryptoBC
    {
        private string algorithm = "SHA256withECDSA";
        private byte[] sig;
        private byte[] target;
        public CryptoBC(byte[] sig ,byte[] target)
        {
            this.sig = sig;
            this.target = target;
            return;
        }

        public static string GetPublicKeyPEMfromCert(string certPem)
        {
            // 証明書の読み込み
            var pemReader = new PemReader(new StringReader(certPem));
            var readedCert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();

            // Get
            var publicKey = readedCert.GetPublicKey();

            // ToPem
            var mem = new MemoryStream();
            using (var writer = new StreamWriter(mem, Encoding.ASCII)) {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(publicKey);
                pemWriter.Writer.Flush();
            }
            var pem = Encoding.UTF8.GetString(mem.ToArray());

            return pem;
        }

        public bool VerifybyPublicKey(string pubkeyPem)
        {
            var privateKeyReader = new PemReader(new StringReader(pubkeyPem));
            var publicKey = (AsymmetricKeyParameter)privateKeyReader.ReadObject();

            ISigner signer = SignerUtilities.GetSigner(algorithm);
            signer.Init(false, publicKey);

            signer.BlockUpdate(target, 0, target.Length);
            var result = signer.VerifySignature(sig);

            return (result);
        }

    }
}
