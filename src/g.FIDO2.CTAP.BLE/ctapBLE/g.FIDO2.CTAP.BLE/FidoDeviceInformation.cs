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
    internal class FidoDeviceInformation
    {
        public async Task<bool> IsFidoDevice(BluetoothLEDevice dev,string key)
        {
            try {
                Logger.Log("IsFidoDevice");

                // GetGattServicesForUuidAsyc などはCreaters Update(15063)から追加されたAPI。 Anniversary Edition(14393)まで対応する場合 はGetGattServiceを使う
                //var service = dev.GetGattService(GattServiceUuids.DeviceInformation);
                var services = await dev.GetGattServicesForUuidAsync(GattServiceUuids.DeviceInformation, BluetoothCacheMode.Cached);
                if (services.Services.Count <= 0) {
                    Logger.Log("サービス無し");
                    return (false);
                }
                foreach (var service in services.Services) {
                    // forlog
                    //await logService(service);

                    var manufacturerNameString = await checkDeviceInformationService_Characteristics(service, GattCharacteristicUuids.ManufacturerNameString);
                    Logger.Log($"ManufacturerName = {manufacturerNameString}");

                    var modelNumberString = await checkDeviceInformationService_Characteristics(service, GattCharacteristicUuids.ModelNumberString);
                    Logger.Log($"ModelNumber = {modelNumberString}");

                    var serialNumberString = await checkDeviceInformationService_Characteristics(service, GattCharacteristicUuids.SerialNumberString);
                    Logger.Log($"SerialNumber = {serialNumberString}");

                    if(manufacturerNameString== key) {
                        // OK
                        return (true);
                    }
                }
            } catch (Exception ex) {
                Logger.Err(ex);
            }

            return (true);
        }

        private async Task<string> checkDeviceInformationService_Characteristics(GattDeviceService service, Guid characteristicUuid)
        {
            string retval = "";
            try {
                var characteristics = await service.GetCharacteristicsForUuidAsync(characteristicUuid, BluetoothCacheMode.Cached);
                if (characteristics.Characteristics.Count <= 0) {
                    return (retval);
                }

                var chara = characteristics.Characteristics.First();
                if (chara == null) {
                    return (retval);
                }

                if (chara.CharacteristicProperties.HasFlag(GattCharacteristicProperties.Read)) {
                    GattReadResult result = await chara.ReadValueAsync();
                    if (result.Status == GattCommunicationStatus.Success) {
                        var reader = Windows.Storage.Streams.DataReader.FromBuffer(result.Value);
                        byte[] input = new byte[reader.UnconsumedBufferLength];
                        reader.ReadBytes(input);

                        // nullまで
                        int index = input.ToList().FindIndex(x => x == 0x00);
                        if (index > 0) {
                            input = input.Skip(0).Take(index).ToArray();
                        }

                        string text = System.Text.Encoding.ASCII.GetString(input);
                        retval = text.Trim();
                    }
                }
            } catch (Exception ex) {
                Logger.Err(ex);
            } finally {
                Logger.Log($"checkDeviceInformationService_Characteristics UUID={characteristicUuid},value={retval}");
            }
            return (retval);
        }

    }
}
