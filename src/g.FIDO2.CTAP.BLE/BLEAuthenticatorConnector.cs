using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Devices.Bluetooth;

namespace g.FIDO2.CTAP.BLE
{
    /// <summary>
    /// Communication class with BLE authenticator
    /// </summary>
    public class BLEAuthenticatorConnector:AuthenticatorConnector
    {
        public int PacketSizeByte { set; get; } = 0;

        /// <summary>
        /// Connection completed event with BLE Authenticator device 
        /// </summary>
        public event EventHandler ConnectedDevice;

        /// <summary>
        /// Disconnect complete event with BLE Authenticator device 
        /// </summary>
        public event EventHandler DisconnectedDevice;

        /// <summary>
        /// KeepAlive event 
        /// </summary>
        public event EventHandler KeepAlive;

        /// <summary>
        /// constructor
        /// </summary>
        public BLEAuthenticatorConnector() { }

        /// <summary>
        /// Connect with BLE Authenticator devices
        /// </summary>
        public async Task<bool> ConnectAsync(ulong bluetoothAddress)
        {
            bleDevice = await BluetoothLEDevice.FromBluetoothAddressAsync(bluetoothAddress);

            if (checkDeviceInformation) {
                // Debug DeviceInformationチェック | check
                var devinfo = new FidoDeviceInformation();
                if (await devinfo.IsFidoDevice(bleDevice, "") == false) {
                    return false;
                }

                Logger.Log($"Device Information ManufacturerName: {devinfo.ManufacturerNameString}");
                Logger.Log($"Device Information ModelNumberString: {devinfo.ModelNumberString}");
                Logger.Log($"Device Information SerialNumberString: {devinfo.SerialNumberString}");
            }

            // イベントハンドラ追加 | Added event handler
            bleDevice.ConnectionStatusChanged += onConnectionStateChange;

            {
                // FIDOのサービスをGET | GET FIDO Service
                service_Fido = await this.getFIDOService(bleDevice);
                if (service_Fido == null) {
                    // サービス無し | No service
                    Logger.Err("Error Connect FIDO Service");
                    return false;
                }

                // Characteristicアクセス | Characteristic access
                // - コマンド送信ハンドラ設定 | Command transmission handler setting
                // - 応答受信ハンドラ設定 | Response reception handler setting
                {
                    if (PacketSizeByte <= 0) {
                        // FIDO Control Point Length(Read-2byte)
                        var readVal = await readCharacteristicValue(service_Fido, Common.Gatt_Characteristic_FIDO_Control_Point_Length_GUID);
                        if (readVal != null) {
                            this.PacketSizeByte = g.FIDO2.Common.ToUInt16(readVal, 0, true);
                            Logger.Log($"Got PacketSize: {this.PacketSizeByte}");
                        }
                    }

                    /*
                    // FIDO Service Revision(Read)
                    await DebugMethods.OutputLog(Service_Fido, GattCharacteristicUuids.SoftwareRevisionString);

                    // FIDO Service Revision Bitfield(Read/Write-1+byte)
                    await DebugMethods.OutputLog(Service_Fido, new Guid("F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB"));
                    */

                    // FIDO Status(Notify) 受信データ | received data
                    {
                        var characteristics = await service_Fido.GetCharacteristicsForUuidAsync(Common.GATT_CHARACTERISTIC_FIDO_STATUS_GUID);
                        if (characteristics.Characteristics.Count <= 0) {
                            Logger.Err("Error Connect Characteristic FIDO Status(Notify)");
                            return false;
                        }
                        this.characteristic_Receive = characteristics.Characteristics.First();
                        if (this.characteristic_Receive == null) {
                            Logger.Err("Error Connect Characteristic FIDO Status(Notify)");
                            return false;
                        }

                        receiver = new CTAPBLEReceiver();
                        receiver.KeepAlive += this.KeepAlive;
                        if (this.characteristic_Receive.CharacteristicProperties.HasFlag(GattCharacteristicProperties.Notify)) {
                            // イベントハンドラ追加 | Added event handler
                            this.characteristic_Receive.ValueChanged += receiver.OnReceiveFromDevice;

                            // これで有効になる | This will enable
                            //A read permission error can also be the result of the authenticator sending incorrect response data
                            await this.characteristic_Receive.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Notify);
                        }
                    }

                    // FIDO Control Point(Write) 送信データ | Transmission data
                    {
                        var characteristics = await service_Fido.GetCharacteristicsForUuidAsync(Common.GATT_CHARACTERISTIC_FIDO_CONTROL_POINT_GUID);
                        if (characteristics.Characteristics.Count <= 0) {
                            Logger.Err("Error Connect CharacteristicFIDO Control Point(Write)");
                            return false;
                        }

                        this.characteristic_Send = characteristics.Characteristics.First();
                        if (this.characteristic_Send == null) {
                            Logger.Err("Error Connect Characteristic FIDO Control Point(Write)");
                            return false;
                        }
                    }

                    Logger.Log("Connect BLE Authenticator!");
                    ConnectedDevice?.Invoke(this, EventArgs.Empty);
                }
            }
            return true;
        }

        /// <summary>
        /// Disconnect from BLE Authenticator device
        /// </summary>
        public bool Disconnect()
        {
            if (service_Fido != null) {
                service_Fido.Dispose();
                Logger.Log("FIDO Service Disposed");
            }

            if (bleDevice != null) {
                bleDevice.Dispose();
                Logger.Log("BLE Device Disposed");
            }
            Logger.Log("BLE FIDOキーと切断しました | Disconnected with FIDO key");

            return true;
        }

        // private member
        private BluetoothLEDevice bleDevice;
        private GattDeviceService service_Fido;
        private GattCharacteristic characteristic_Send;
        private GattCharacteristic characteristic_Receive;
        private CTAPBLEReceiver receiver;
        private bool checkDeviceInformation = true;

        protected override async Task<(DeviceStatus devSt, CTAPResponse ctapRes)> sendCommandandResponseAsync(CTAPCommand cmd, CTAPResponse res)
        {
            try {
                // 送信コマンドを作成(byte[]) | Create send command
                var payload = cmd.CreatePayload();

                // 送信して、応答受信(byte[]) | Send and receive response (byte [])
                var sender = new CTAPBLESender(PacketSizeByte,receiver);
                var response = await sender.SendCommandandResponseAsync(characteristic_Send, payload, 10000);

                // 応答をパース | Parse response
                res.Parse(response.ctapRes);
                res.SendPayloadJson = cmd.PayloadJson;

                return (response.devSt,res);
            } catch (Exception ex) {
                Logger.Log($"Exception...{ex.Message})");
                return (DeviceStatus.Unknown, null);
            }
        }

        private void onConnectionStateChange(BluetoothLEDevice sender, object arg)
        {
            Logger.Log($"onConnectionStateChange");
            Logger.Log($"-> Name={sender.Name}");
            Logger.Log($"-> ConnectionStatus={sender.ConnectionStatus}");

            if (sender.ConnectionStatus == BluetoothConnectionStatus.Connected) {
                Logger.Log($"Connected!");
                //OnConnected(this.resbuff.bleMeasuringDeviceInfo);
            } else if (sender.ConnectionStatus == BluetoothConnectionStatus.Disconnected) {
                Logger.Log($"Disconnected!");
                this.Disconnect();

                // イベント発生させる | Generate an event
                DisconnectedDevice?.Invoke(this, EventArgs.Empty);
            }
        }

        private async Task<byte[]> readCharacteristicValue(GattDeviceService service, Guid characteristicUuid)
        {
            byte[] retval = null;
            try {
                var characteristics = await service.GetCharacteristicsForUuidAsync(characteristicUuid, BluetoothCacheMode.Uncached);
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
                        retval = new byte[reader.UnconsumedBufferLength];
                        reader.ReadBytes(retval);

                        //hex = Common.BytesToHexString(input);

                        // nullまで | Up to null
                        //int index = input.ToList().FindIndex(x => x == 0x00);
                        //if (index > 0) {
                        //    retval = input.Skip(0).Take(index).ToArray();
                        //}

                        //string text = System.Text.Encoding.ASCII.GetString(input);
                        //ascii = text.Trim();
                    }
                }
            } catch (Exception ex) {
                Logger.Err(ex);
            } finally {
                //Logger.Log($"Characteristic UUID={characteristicUuid}");
                //Logger.Log($"- value HEX={hex}");
                //Logger.Log($"- value Ascii={ascii}");
            }
            return (retval);
        }

        private async Task<GattDeviceService> getFIDOService(BluetoothLEDevice device)
        {
            GattDeviceService ret=null;
            Logger.Log("Connect FIDO Service");

            //serviceを取得 | get service
            GattDeviceServicesResult servicesResult = await device.GetGattServicesAsync(BluetoothCacheMode.Uncached);
            if (servicesResult.Status == GattCommunicationStatus.Success) {
                var services = servicesResult.Services;
                foreach (GattDeviceService service in services) {
                    string uuid = service.Uuid.ToString();
                    if (uuid.ToLower() == Common.Gatt_Service_FIDO_UUID) {
                        ret = service;
                        break;
                    }
                    /*
                    //characteristicを取得 | Get characteristic
                    GattCharacteristicsResult characteristicsResult = await service.GetCharacteristicsAsync();
                    if (characteristicsResult.Status == GattCommunicationStatus.Success) {
                        var characteristics = characteristicsResult.Characteristics;
                        foreach (GattCharacteristic characteristic in characteristics) {
                           string chuuid = "characterisitics uuid: " + characteristic.Uuid;
                        }
                    }
                    */
                }
            }

            // こっちはダメ | This is no good
            //var services = await bleDevice.GetGattServicesForUuidAsync(Common.Gatt_Service_FIDO_GUID);
            //if (services.Services.Count <= 0) {
            //    // サービス無し | No service
            //    Logger.Err("Error Connect FIDO Service");
            //    return false;
            //}
            //ret = services.Services.First();

            // この時点で接続状態になっているはず | Should be connected at this point
            if (device.ConnectionStatus != BluetoothConnectionStatus.Connected) {
                Logger.Err("Error getFIDOService");
                return null;
            }

            return ret;

        }
    }
}
