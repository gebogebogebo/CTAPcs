﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP.HID
{
    public class HidParam
    {
        public int VendorId { get; set; }
        public int ProductId { get; set; }
        public string Something { get; set; }

        public HidParam(int vendorId, int productId, string something)
        {
            this.VendorId = vendorId;
            this.ProductId = productId;
            this.Something = something;
        }
        public HidParam(int vendorId, int productId)
        {
            this.VendorId = vendorId;
            this.ProductId = productId;
            this.Something = "";
        }
        public HidParam(int vendorId)
        {
            this.VendorId = vendorId;
            this.ProductId = 0x00;
            this.Something = "";
        }

        public static List<HidParam> GetDefaultParams()
        {
            var ret = new List<HidParam>();

            ret = new List<HidParam>();

            // Yubikey
            //ret.Add(new hidparam(0x1050, 0x0120));
            ret.Add(new HidParam(0x1050));

            // BioPass FIDO2
            //ret.Add(new HidParam(0x096E,0x85D,"fido"));
            ret.Add(new HidParam(0x096E,0,"fido"));

            // Solo Key
            ret.Add(new HidParam(0x0483));

            // OpenSK
            ret.Add(new HidParam(0x1915));

            // Nitrokey FIDO2
            ret.Add(new HidParam(0x20a0, 0x42b1));

            return (ret);
        }
    }

}
