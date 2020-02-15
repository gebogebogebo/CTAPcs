using System;
using System.Collections.Generic;
using System.Linq;

namespace g.FIDO2
{
    public class Attestation
    {
        public string Fmt { get; set; }
        public byte[] RpIdHash { get; set; }
        public bool Flags_UserPresentResult { get; set; }
        public bool Flags_UserVerifiedResult { get; set; }
        public bool Flags_AttestedCredentialDataIncluded { get; set; }
        public bool Flags_ExtensionDataIncluded { get; set; }
        public int SignCount { get; set; }
        public byte[] Aaguid { get; set; }
        public byte[] CredentialId { get; set; }
        public string CredentialPublicKey { get; set; }
        public byte[] CredentialPublicKeyByte { get; set; }
        public byte[] AuthData { get; set; }

        public int AttStmtAlg { get; set; }
        public byte[] AttStmtSig { get; set; }
        public byte[] AttStmtX5c { get; set; }
    }
}

