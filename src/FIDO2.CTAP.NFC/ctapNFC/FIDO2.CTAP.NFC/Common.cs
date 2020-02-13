using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP.NFC
{
    public class Common : g.FIDO2.CTAP.Common
    {
    }

    public class NfcParam
    {
        public static List<string> GetDefalutReaders()
        {
            return (new List<string>());
        }
    }

}
