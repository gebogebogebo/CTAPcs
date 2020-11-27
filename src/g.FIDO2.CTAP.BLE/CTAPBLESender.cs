using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Windows.Devices.Bluetooth.GenericAttributeProfile;
using System.Runtime.InteropServices.WindowsRuntime;

namespace g.FIDO2.CTAP.BLE
{
    internal class CTAPBLESender
    {
        //public int ReceiveResponseTimeoutmillisecond = 3000;

        private int packetSizeByte;
        private CTAPBLEReceiver receiver;
        public CTAPBLESender(int packetSizeByte,CTAPBLEReceiver r)
        {
            this.packetSizeByte = packetSizeByte;
            receiver = r;
        }

        public async Task<(DeviceStatus devSt, byte[] ctapRes)> SendCommandandResponseAsync(GattCharacteristic ch, byte[] payload, int timeoutms)
        {
            byte[] byteresponse = null;
            receiver.ClearBuffer();

            var sendData = new List<byte>();

            // Command identifier - MSG
            sendData.Add(0x83);

            //Calculate the payload length as a two-byte big endian and add to data
            //https://docs.microsoft.com/en-us/dotnet/api/system.bitconverter
            var length = (short)payload.Length;
            var lengthBytes = BitConverter.GetBytes(length);
            if (BitConverter.IsLittleEndian) Array.Reverse(lengthBytes);

            sendData.AddRange(lengthBytes);

            // Data (s is equal to the length)
            sendData.AddRange(payload);

            var frames = new List<byte[]>();
            if (this.packetSizeByte > 0 && payload.Length > this.packetSizeByte) {
                // Frame 0
                frames.Add(sendData.Take(this.packetSizeByte).ToArray());

                // Frame 1
                var chunked = g.FIDO2.Common.Chunk(sendData.Skip(this.packetSizeByte).ToArray(), this.packetSizeByte-1);
                foreach(var one in chunked.Select((value, index) => new { value, index })) {
                    var tmp = new List<byte>();
                    // Packet sequence
                    tmp.Add((byte)one.index);
                    // Packet data
                    tmp.AddRange(one.value);
                    frames.Add(tmp.ToArray());
                }

            } else {
                frames.Add(sendData.ToArray());
            }

            bool res = false;
            foreach (var frame in frames) {
                res = await CTAPBLESender.sendCommand(ch, frame);
                if( res == false) {
                    break;
                }
            }

            if (res) {

                // Wait Response
                int delay = 10;
                int waitCounter = timeoutms / delay;
                for (int intIc = 0; intIc < waitCounter; intIc++) {
                    await Task.Delay(delay);
                    if (receiver.IsReceived) {
                        break;
                    }
                }
                if (!receiver.IsReceived) {
                    // timeout
                    Logger.Err("Wait Response Timeout");
                    return (DeviceStatus.Timeout, null);
                }

                // 応答受信 | Receive response
                byteresponse = receiver.GetBuffer();
            }

            if (byteresponse == null) {
                Logger.Err("Response Error");
                return (DeviceStatus.Unknown , null);
            }

            return (DeviceStatus.Ok, byteresponse);
        }

        public static async Task<bool> sendCommand(GattCharacteristic Characteristic_Send,byte[] command)
        {
            bool ret = false;
            try {
                if (command == null) {
                    return (ret);
                }

                // log
                Logger.Log($"send Command...");
                Logger.Log($"{BitConverter.ToString(command).ToLower()}");

                //ReceveData = new List<byte>();

                var result = await Characteristic_Send.WriteValueAsync(command.AsBuffer(), GattWriteOption.WriteWithResponse);
                if (result != GattCommunicationStatus.Success) {
                    // error
                    return (false);
                }
                ret = true;
            } catch (Exception ex) {
                Logger.Log($"Exception...{ex.Message})");
            }
            return (ret);
        }

    }
}
