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
        /// constructor
        /// </summary>
        public BLEAuthenticatorConnector() { }

        /// <summary>
        /// Connect with BLE Authenticator devices
        /// </summary>
        public async Task<bool> ConnectAsync(ulong bluetoothAddress)
        {
            bleDevice = await BluetoothLEDevice.FromBluetoothAddressAsync(bluetoothAddress);

            if(checkDeviceInformation) {
                // Debug DeviceInformationチェック
                var devinfo = new FidoDeviceInformation();
                if (await devinfo.IsFidoDevice(bleDevice,"") == false) {
                    return false;
                }
            }

            // イベントハンドラ追加
            bleDevice.ConnectionStatusChanged += onConnectionStateChange;

            {
                // FIDOのサービスをGET
                {
                    //addLog("Connect FIDO Service");
                    var services = await bleDevice.GetGattServicesForUuidAsync(Common.Gatt_Service_FIDO_GUID);
                    if (services.Services.Count <= 0) {
                        // サービス無し
                        Logger.Err("Error Connect FIDO Service");
                        return false;
                    }
                    service_Fido = services.Services.First();
                }

                // Characteristicアクセス
                // - コマンド送信ハンドラ設定
                // - 応答受信ハンドラ設定
                {
                    if (PacketSizeByte <= 0) {
                        // FIDO Control Point Length(Read-2byte)
                        var readVal = await readCharacteristicValue(service_Fido, Common.Gatt_Characteristic_FIDO_Control_Point_Length_GUID);
                        if( readVal != null) {
                            this.PacketSizeByte = Common.ToUInt16(readVal, 0, true);
                        }
                    }

                    /*
                    // FIDO Service Revision(Read)
                    await DebugMethods.OutputLog(Service_Fido, GattCharacteristicUuids.SoftwareRevisionString);

                    // FIDO Service Revision Bitfield(Read/Write-1+byte)
                    await DebugMethods.OutputLog(Service_Fido, new Guid("F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB"));
                    */

                    // FIDO Status(Notify) 受信データ
                    {
                        var characteristics = await service_Fido.GetCharacteristicsForUuidAsync(Common.GATT_CHARACTERISTIC_FIDO_STATUS_GUID);
                        if (characteristics.Characteristics.Count > 0) {
                            this.characteristic_Receive = characteristics.Characteristics.First();
                            if (this.characteristic_Receive == null) {
                                Logger.Err("Error Connect Characteristic FIDO Status(Notify)");
                            } else {
                                receiver = new CTAPBLEReceiver();

                                if (this.characteristic_Receive.CharacteristicProperties.HasFlag(GattCharacteristicProperties.Notify)) {
                                    // イベントハンドラ追加
                                    this.characteristic_Receive.ValueChanged += receiver.OnReceiveFromDevice;

                                    // これで有効になる
                                    await this.characteristic_Receive.WriteClientCharacteristicConfigurationDescriptorAsync(GattClientCharacteristicConfigurationDescriptorValue.Notify);
                                }
                            }
                        }
                    }

                    // FIDO Control Point(Write) 送信データ
                    {
                        var characteristics = await service_Fido.GetCharacteristicsForUuidAsync(Common.GATT_CHARACTERISTIC_FIDO_CONTROL_POINT_GUID);
                        if (characteristics.Characteristics.Count > 0) {
                            this.characteristic_Send = characteristics.Characteristics.First();
                            if (this.characteristic_Send == null) {
                                Logger.Err("Error Connect Characteristic FIDO Control Point(Write)");
                            }
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
            Logger.Log("BLE FIDOキーと切断しました");
            return true;
        }

        // private member
        private BluetoothLEDevice bleDevice;
        private GattDeviceService service_Fido;
        private GattCharacteristic characteristic_Send;
        private GattCharacteristic characteristic_Receive;
        private CTAPBLEReceiver receiver;
        private bool checkDeviceInformation = false;

        internal override async Task<(DeviceStatus devSt, CTAPResponse ctapRes)> sendCommandandResponseAsync(CTAPCommand cmd, CTAPResponse res)
        {
            try {
                // 送信コマンドを作成(byte[])
                var payload = cmd.CreatePayload();

                // 送信して、応答受信(byte[])
                var sender = new CTAPBLESender(PacketSizeByte,receiver);
                var response = await sender.SendCommandandResponseAsync(characteristic_Send, payload, 10000);

                // 応答をパース
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

                // イベント発生させる
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

                        // nullまで
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

    }
}
