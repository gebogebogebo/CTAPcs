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
    public class BLEAuthenticatorConnector
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

        /// <summary>
        /// CTAP-Command GetInfo
        /// </summary>
        public async Task<CTAPResponseGetInfo> GetInfoAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandGetInfo(), new CTAPResponseGetInfo());
            return (CTAPResponseGetInfo)ret;
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getRetries
        /// </summary>
        public async Task<CTAPResponseClientPIN2_getRetries> ClientPINgetRetriesAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandClientPIN_getRetries(), new CTAPResponseClientPIN2_getRetries());
            return (CTAPResponseClientPIN2_getRetries)ret;
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getKeyAgreement
        /// </summary>
        public async Task<CTAPResponseClientPIN2_getKeyAgreement> ClientPINgetKeyAgreementAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandClientPIN_getKeyAgreement(), new CTAPResponseClientPIN2_getKeyAgreement());
            return (CTAPResponseClientPIN2_getKeyAgreement)ret;
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getPINToken use PIN string
        /// </summary>
        public async Task<CTAPResponseClientPIN2_getPINToken> ClientPINgetPINTokenAsync(string pin)
        {
            var ret = (CTAPResponseClientPIN2_getKeyAgreement)await sendCommandandResponseAsync(new CTAPCommandClientPIN_getKeyAgreement(), new CTAPResponseClientPIN2_getKeyAgreement());

            COSE_Key myKeyAgreement;
            var sharedSecret = CTAPCommandClientPIN.CreateSharedSecret(ret.KeyAgreement, out myKeyAgreement);

            var pinHashEnc = CTAPCommandClientPIN.CreatePinHashEnc(pin, sharedSecret);

            return await ClientPINgetPINTokenAsync(myKeyAgreement, pinHashEnc, sharedSecret);
        }

        /// <summary>
        /// CTAP-Command ClientPIN - getPINToken
        /// </summary>
        public async Task<CTAPResponseClientPIN2_getPINToken> ClientPINgetPINTokenAsync(COSE_Key keyAgreement,byte[] pinHashEnc,byte[] sharedSecret)
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandClientPIN_getPINToken(keyAgreement, pinHashEnc), new CTAPResponseClientPIN2_getPINToken(sharedSecret));
            return (CTAPResponseClientPIN2_getPINToken)ret;
        }

        /// <summary>
        /// CTAP-Command GetAssertion use pinAuth
        /// </summary>
        public async Task<CTAPResponseGetAssertion> GetAssertionAsync(CTAPCommandGetAssertionParam param,byte[] pinAuth=null)
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandGetAssertion(param, pinAuth), new CTAPResponseGetAssertion());
            return (CTAPResponseGetAssertion)ret;
        }

        /// <summary>
        /// CTAP-Command GetAssertion use PIN string
        /// </summary>
        public async Task<CTAPResponseGetAssertion> GetAssertionAsync(CTAPCommandGetAssertionParam param, string pin)
        {
            var token = await ClientPINgetPINTokenAsync(pin);
            if(token.Status != 0) {
                return new CTAPResponseGetAssertion(token);
            }

            var pinAuth = CTAPCommandClientPIN.CreatePinAuth(param.ClientDataHash, token.PinToken);

            var ret = await sendCommandandResponseAsync(new CTAPCommandGetAssertion(param, pinAuth), new CTAPResponseGetAssertion());
            return (CTAPResponseGetAssertion)ret;
        }

        /// <summary>
        /// CTAP-Command GetNextAssertion use pinAuth
        /// </summary>
        public async Task<CTAPResponseGetAssertion> GetNextAssertionAsync()
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandGetNextAssertion(), new CTAPResponseGetAssertion());
            return (CTAPResponseGetAssertion)ret;
        }

        /// <summary>
        /// CTAP-Command MakeCredential use pinAuth
        /// </summary>
        public async Task<CTAPResponseMakeCredential> MakeCredentialAsync(CTAPCommandMakeCredentialParam param, byte[] pinAuth = null)
        {
            var ret = await sendCommandandResponseAsync(new CTAPCommandMakeCredential(param, pinAuth), new CTAPResponseMakeCredential());
            return (CTAPResponseMakeCredential)ret;
        }

        /// <summary>
        /// CTAP-Command MakeCredential use PIN string
        /// </summary>
        public async Task<CTAPResponseMakeCredential> MakeCredentialAsync(CTAPCommandMakeCredentialParam param, string pin)
        {
            var token = await ClientPINgetPINTokenAsync(pin);
            if (token.Status != 0) {
                return new CTAPResponseMakeCredential(token);
            }

            var pinAuth = CTAPCommandClientPIN.CreatePinAuth(param.ClientDataHash, token.PinToken);

            var ret = await sendCommandandResponseAsync(new CTAPCommandMakeCredential(param, pinAuth), new CTAPResponseMakeCredential());
            return (CTAPResponseMakeCredential)ret;
        }


        // private member
        private BluetoothLEDevice bleDevice;
        private GattDeviceService service_Fido;
        private GattCharacteristic characteristic_Send;
        private GattCharacteristic characteristic_Receive;
        private CTAPBLEReceiver receiver;
        private bool checkDeviceInformation = false;

        private async Task<CTAPResponse> sendCommandandResponseAsync(CTAPCommand cmd, CTAPResponse res)
        {
            try {
                // 送信コマンドを作成(byte[])
                var payload = cmd.CreatePayload();

                // 送信して、応答受信(byte[])
                var sender = new CTAPBLESender(PacketSizeByte,receiver);
                var response = await sender.SendCommandandResponseAsync(characteristic_Send, payload, 10000);

                // 応答をパース
                res.Parse(response);
                res.SendPayloadJson = cmd.PayloadJson;

                return res;
            } catch (Exception ex) {
                Logger.Log($"Exception...{ex.Message})");
                return null;
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
