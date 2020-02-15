using System.Security.Cryptography;

namespace g.FIDO2.CTAP
{
    public class Common:g.FIDO2.Common
    {
        static public byte[] CreateClientDataHash(string challenge)
        {
            byte[] input = System.Text.Encoding.ASCII.GetBytes(challenge);
            return (CreateClientDataHash(input));
        }

        static public byte[] CreateClientDataHash(byte[] challenge)
        {
            SHA256 sha = new SHA256CryptoServiceProvider();
            var cdh = sha.ComputeHash(challenge);
            return (cdh);
        }

        static public bool IsAdministrator()
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
    }
}
