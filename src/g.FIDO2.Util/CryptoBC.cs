﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

using Org.BouncyCastle.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Operators;
// Org.BouncyCastle.X509.X509CertificateとSystem.Security.Cryptographic.X509Certificates.X509Certificateの名前が重複するので、直接名前空間を使わないことにする
using MsX509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1;

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

        public static MsX509Certificate2 CreateCertificate(string pubkeyPem)
        {
            // ここで生成したPrivateKeyで署名するのでこの証明書の署名には意味がない
            // 鍵のジェネレータ
            var randGen = new CryptoApiRandomGenerator();
            var rand = new SecureRandom(randGen);
            var param = new KeyGenerationParameters(rand, 2048);

            // 鍵生成
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(param);
            var keyPair = keyGen.GenerateKeyPair();


            var privateKeyReader = new PemReader(new StringReader(pubkeyPem));
            var publicKey = (AsymmetricKeyParameter)privateKeyReader.ReadObject();

            // 証明書の属性
            var attr = new Dictionary<DerObjectIdentifier, string>()
            {
                { X509Name.CN, "test" },
                { X509Name.C, "Japan" },
                { X509Name.OU, "None" },
            };
            var ord = new List<DerObjectIdentifier>()
            {
                X509Name.CN,
                X509Name.C,
                X509Name.OU,
            };
            var issuerDN = new X509Name(ord, attr);

            // シリアル番号の文字列表現(10進数)
            string serialString = "123";

            // これより前の時刻は証明書は無効
            DateTime notBefore = DateTime.Now;

            // これより後の時刻は証明書は無効
            DateTime notAfter = DateTime.Now;

            var x509gen = new X509V3CertificateGenerator();
            var serial = new BigInteger(serialString);
            x509gen.SetSerialNumber(serial);
            x509gen.SetIssuerDN(issuerDN);
            x509gen.SetSubjectDN(issuerDN);
            x509gen.SetNotBefore(notBefore);
            x509gen.SetNotAfter(notAfter);
            x509gen.SetPublicKey(publicKey);

            // SHA256+RSAで署名する
            var signerFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, keyPair.Private);
            var x509 = x509gen.Generate(signerFactory);

            return new MsX509Certificate2(DotNetUtilities.ToX509Certificate(x509));
        }
    }
}
