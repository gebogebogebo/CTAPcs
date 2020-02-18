using System;

namespace g.FIDO2
{
    [Serializable]
    public class Assertion
    {
        public byte[] RpIdHash { get; set; }
        public bool Flags_UserPresentResult { get; set; }
        public bool Flags_UserVerifiedResult { get; set; }
        public bool Flags_AttestedCredentialDataIncluded { get; set; }
        public bool Flags_ExtensionDataIncluded { get; set; }

        public int SignCount { get; set; }
        public byte[] Aaguid { get; set; }

        public int NumberOfCredentials { get; set; }

        public byte[] Signature { get; set; }
        public byte[] User_Id { get; set; }
        public string User_Name { get; set; }
        public string User_DisplayName { get; set; }

        public byte[] AuthData { get; set; }

        public byte[] CredentialId { get; set; }
    }
}

