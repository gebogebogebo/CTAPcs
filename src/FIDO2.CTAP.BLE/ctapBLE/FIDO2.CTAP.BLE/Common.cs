using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace g.FIDO2.CTAP.BLE
{
    public class Common : g.FIDO2.CTAP.Common
    {
        // Service 
        public static readonly string Gatt_Service_FIDO_UUID = "0000fffd-0000-1000-8000-00805f9b34fb";
        public static readonly Guid Gatt_Service_FIDO_GUID = new Guid(Gatt_Service_FIDO_UUID);

        // Characteristic FIDO Control Point(Write)
        public static readonly string GATT_CHARACTERISTIC_FIDO_CONTROL_POINT_UUID = "F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB";
        public static readonly Guid GATT_CHARACTERISTIC_FIDO_CONTROL_POINT_GUID = new Guid(GATT_CHARACTERISTIC_FIDO_CONTROL_POINT_UUID);

        // Characteristic FIDO Status(Notify)
        public static readonly string GATT_CHARACTERISTIC_FIDO_STATUS_UUID = "F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB";
        public static readonly Guid GATT_CHARACTERISTIC_FIDO_STATUS_GUID = new Guid(GATT_CHARACTERISTIC_FIDO_STATUS_UUID);

        // FIDO Control Point Length(Read-2byte)
        public static readonly string Gatt_Characteristic_FIDO_Control_Point_Length_UUID = "F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB";
        public static readonly Guid Gatt_Characteristic_FIDO_Control_Point_Length_GUID = new Guid(Gatt_Characteristic_FIDO_Control_Point_Length_UUID);

        // FIDO Service Revision Bitfield(Read/Write-1+byte)
        public static readonly string Gatt_Characteristic_FIDO_Service_Revision_Bitfield_UUID = "F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB";
        public static readonly Guid Gatt_Characteristic_FIDO_Service_Revision_Bitfield_GUID = new Guid(Gatt_Characteristic_FIDO_Service_Revision_Bitfield_UUID);
    }
}
