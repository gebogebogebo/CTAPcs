using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace g.FIDO2.CTAP
{
    internal class CTAPCommandGetInfo : CTAPCommand
    {
        public override byte[] CreatePayload()
        {
            return (create(CTAPCommandType.authenticatorGetInfo, null));
        }

    }

}
