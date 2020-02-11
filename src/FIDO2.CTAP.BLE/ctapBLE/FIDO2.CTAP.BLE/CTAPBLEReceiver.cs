using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using g.FIDO2.CTAP;

namespace g.FIDO2.CTAP.BLE
{
    internal class CTAPBLEReceiver
    {
        public bool IsReceived { get; private set; }

        private BLEResponsePacket receiveData;

        public CTAPBLEReceiver()
        {
            receiveData = new BLEResponsePacket();
        }
        
        public void ClearBuffer()
        {
            IsReceived = false;
            receiveData.Clear();
        }

        public byte[] GetBuffer()
        {
            return receiveData.Get();
        }

        public void OnReceiveFromDevice(GattCharacteristic sender, GattValueChangedEventArgs eventArgs)
        {
            Logger.Log($"characteristicChanged...");
            Logger.Log($"- Length={eventArgs.CharacteristicValue.Length}");
            if (eventArgs.CharacteristicValue.Length <= 0) {
                return;
            }

            byte[] data = new byte[eventArgs.CharacteristicValue.Length];
            Windows.Storage.Streams.DataReader.FromBuffer(eventArgs.CharacteristicValue).ReadBytes(data);

            // for log
            {
                var tmp = BitConverter.ToString(data);
                Logger.Log($"- Data...");
                Logger.Log($"{tmp}");
            }

            // parse
            {
                // [0] STAT
                if (data[0] == 0x81) {
                    Logger.Log($"PING");
                } else if (data[0] == 0x82) {
                    Logger.Log($"KEEPALIVE");
                } else if (data[0] == 0x83) {
                    Logger.Log($"MSG");
                    IsReceived = false;
                    receiveData = new BLEResponsePacket(data);
                } else if (data[0] == 0xbe) {
                    // CANCEL
                    Logger.Log($"CANCEL");
                } else if (data[0] == 0xbf) {
                    // ERROR
                    Logger.Log($"ERROR");
                } else {
                    Logger.Log($"next MSG?");
                    receiveData.Add(data);
                }
            }

            if (receiveData != null) {
                if (receiveData.IsReceiveComplete()) {
                    IsReceived = true;
                    Logger.Log("<<<Receive Complete>>>");
                }
            }

            return;
        }

    }
}
