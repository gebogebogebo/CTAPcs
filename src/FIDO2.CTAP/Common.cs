using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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

    }
}
