using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace g.FIDO2.Util
{
    public class Verifier
    {
        public static byte[] CreateChallenge()
        {
            byte[] random = new byte[32];
            using (var rng = new RNGCryptoServiceProvider()) {
                //バイト配列に暗号化に使用する厳密な0以外の値のランダムシーケンス
                //Random sequence of exact nonzero values used for encryption on a byte array
                rng.GetNonZeroBytes(random);
            }
            return random;
        }

        protected bool VerifyPublicKey(string publickey, byte[] challenge, byte[] authData, byte[] sig)
        {
            var sigBase = new List<byte>();
            sigBase.AddRange(authData.ToList());

            using (var sha256 = new SHA256CryptoServiceProvider())
            {
                var cdh = sha256.ComputeHash(challenge);
                sigBase.AddRange(cdh.ToList());
            }

            // Verify
            return new CryptoBC(sig, sigBase.ToArray()).VerifybyPublicKey(publickey);
        }

        protected bool VerifyRpId(string rpid,byte[] rpidHash)
        {
            //Authenticator did not return a valid rpidHash
            if (rpidHash == null) return false;

            // SHA-256(rpid) == attestation.RpIdHash
            byte[] rpidbyte = System.Text.Encoding.ASCII.GetBytes(rpid);
            SHA256 sha = new SHA256CryptoServiceProvider();
            byte[] rpidbytesha = sha.ComputeHash(rpidbyte);
            return (rpidbytesha.SequenceEqual(rpidHash));
        }

    }


    public class AttestationVerifier:Verifier
    {
        public class Result
        {
            public bool IsSuccess { get; internal set; } = false;
            public byte[] CredentialID { get; internal set; } = null;
            public string PublicKeyPem { get; internal set; } = "";
        }

        public Result Verify(string rpid, byte[] challenge, Attestation att)
        {
            if (VerifyRpId(rpid, att.RpIdHash) == false) return new Result();
            return (Verify(challenge, att));
        }

        protected Result Verify(byte[] challenge, Attestation att)
        {
            var result = new Result();

            // Verifyの結果によらず | Regardless of the result of Verify
            {
                var decAuthdata = new DecodedAuthData();
                decAuthdata.Decode(att.AuthData);
                result.CredentialID = decAuthdata.CredentialId;
                result.PublicKeyPem = decAuthdata.PublicKeyPem;
            }

            //If an x5c certificate is used for attestation (attCA)
            if (att.AttStmtX5c != null)
            {
                var cert = DerConverter.ToPemCertificate(att.AttStmtX5c);
                var publicKeyforVerify = CryptoBC.GetPublicKeyPEMfromCert(cert);
                if (!string.IsNullOrEmpty(publicKeyforVerify))
                {
                    result.IsSuccess = VerifyPublicKey(publicKeyforVerify, challenge, att.AuthData, att.AttStmtSig);
                }
            }
            //Self attestation (signature uses credential keypair instead of attestation keypair)
            else if (att.AttStmtAlg != 0 && att.AttStmtSig != null)
            {
                if (!string.IsNullOrEmpty(result.PublicKeyPem))
                {
                    result.IsSuccess = VerifyPublicKey(result.PublicKeyPem, challenge, att.AuthData, att.AttStmtSig);
                }
            }

            //TODO: Implement check for ECDAA attestation
            //8.2 https://www.w3.org/TR/webauthn/#packed-attestation

            return result;
        }

        public X509Certificate2 CreateSelfSignedCertificate(Result result,string rpName,string userName,TimeSpan expirationDate)
        {
            DateTime notBefore=DateTime.Now;
            DateTime notAfter=notBefore+expirationDate;
            return (CryptoBC.CreateSelfSignedCertificate(result?.PublicKeyPem, rpName, userName, "g.FIDO2.Util", "AttestationVerifier", notBefore, notAfter));
        }
    }

    public class AssertionVerifier : Verifier
    {
        public class Result
        {
            public bool IsSuccess;
        }

        public Result Verify(string rpid, string publicKey, byte[] challenge, Assertion ass)
        {
            if (VerifyRpId(rpid, ass.RpIdHash) == false) return new Result();
            return (Verify(publicKey, challenge, ass));
        }

        protected Result Verify(string publicKey, byte[] challenge,Assertion ass)
        {
            var result = new Result();
            result.IsSuccess = this.VerifyPublicKey(publicKey, challenge, ass.AuthData, ass.Signature);

            return result;
        }

    }

}
