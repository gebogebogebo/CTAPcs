using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace g.FIDO2.Util
{
    public class Verifier
    {
        public static byte[] CreateChallenge()
        {
            byte[] random = new byte[32];
            using (var rng = new RNGCryptoServiceProvider()) {
                //バイト配列に暗号化に使用する厳密な0以外の値のランダムシーケンス
                rng.GetNonZeroBytes(random);
            }
            return random;
        }

        public bool VerifyPublicKey(string publickey, byte[] challenge, byte[] authData, byte[] sig)
        {
            // VerifyTarget = authData + SHA256(challenge)
            byte[] verifyTarget;
            {
                var sigBase = new List<byte>();
                sigBase.AddRange(authData.ToList());

                var cdh = new SHA256CryptoServiceProvider().ComputeHash(challenge);
                sigBase.AddRange(cdh.ToList());

                verifyTarget = sigBase.ToArray();
            }

            // Verify
            var result = new CryptoBC(sig, verifyTarget).VerifybyPublicKey(publickey);

            return result;
        }

    }


    public class AttestationVerifier:Verifier
    {
        public class Result
        {
            public bool IsSuccess;
            public byte[] CredentialID;
            public string PublicKeyPem;
        }

        public Result Verify(byte[] challenge, Attestation att)
        {
            var result = new Result();
            var cert = DerConverter.ToPemCertificate(att.AttStmtX5c);
            var publicKeyforVerify = CryptoBC.GetPublicKeyPEMfromCert(cert);
            result.IsSuccess = VerifyPublicKey(publicKeyforVerify, challenge, att.AuthData, att.AttStmtSig);
            if (result.IsSuccess) {
                var decAuthdata = new DecodedAuthData();
                decAuthdata.Decode(att.AuthData);
                result.CredentialID = decAuthdata.CredentialId;
                result.PublicKeyPem = decAuthdata.PublicKeyPem;
            }

            // PublicKeyを証明書形式にする
            //var cert2 = CryptoBC.CreateCertificate(result.PublicKeyPem);

            return result;
        }

    }

    public class AssertionVerifier : Verifier
    {
        public class Result
        {
            public bool IsSuccess;
        }

        public Result Verify(string publicKey, byte[] challenge,Assertion ass)
        {
            var result = new Result();
            result.IsSuccess = this.VerifyPublicKey(publicKey, challenge, ass.AuthData, ass.Signature);

            return result;
        }

    }

}
