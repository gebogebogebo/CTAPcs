# AuthenticatorConnector Class

FIDOキーと通信するクラスは`AuthenticatorConnector`を継承した以下のクラスです。

- `HIDAuthenticatorConnector`
  - CTAPのHIDインタフェースを実装しています。HIDタイプのFIDOキーと通信します。

- `NFCAuthenticatorConnector`
  - CTAPのNFCインタフェースを実装しています。NFCタイプのFIDOキーと通信します。

- `BLEAuthenticatorConnector`
  - CTAPのBLEインタフェースを実装しています。BLEタイプのFIDOキーと通信します。



## AuthenticatorConnector

以下のメソッドを実装しています。

| method                                                       | 機能                     | 対応するCTAPコマンド                                         |
| ------------------------------------------------------------ | ------------------------ | ------------------------------------------------------------ |
| async Task\<ResponseGetInfo> <br>**GetInfoAsync()**          | FIDOキーの情報を取得する | [authenticatorGetInfo (0x04)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo) |
| async Task\<ResponseMakeCredential> <br>**MakeCredentialAsync**<br>(CTAPCommandMakeCredentialParam param, byte[] pinAuth = null)<br><br>async Task\<ResponseMakeCredential> <br>**MakeCredentialAsync**<br>(CTAPCommandMakeCredentialParam param, string pin) | クレデンシャルの登録     | [authenticatorMakeCredential(0x01)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential) |
| async Task\<ResponseGetAssertion> <br>**GetAssertionAsync**<br>(CTAPCommandGetAssertionParam param, byte[] pinAuth = null)<br><br>async Task\<ResponseGetAssertion> <br>**GetAssertionAsync**<br>(CTAPCommandGetAssertionParam param, string pin) | 認証                     | [authenticatorGetAssertion (0x02)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion) |
| async Task\<ResponseGetAssertion> <br>**GetNextAssertionAsync()** | 認証                     | [authenticatorGetNextAssertion (0x08)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetNextAssertion) |
| async Task\<ResponseClientPIN_getRetries> <br>**ClientPINgetRetriesAsync()** | PINリトライ回数の取得    | [authenticatorGetInfo (0x04)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo) |
| async Task\<ResponseClientPIN_getKeyAgreement> <br>**ClientPINgetKeyAgreementAsync()** | Key Agreementを取得する  | [authenticatorClientPIN (0x06)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN) |
| async Task\<ResponseClientPIN> <br>**ClientPINsetPINAsync**<br>(string newpin) | 初期PINを設定する        | [authenticatorClientPIN (0x06)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN) |
| async Task\<ResponseClientPIN> <br>**ClientPINchangePINAsync**<br>(string newpin, string currentpin) | PINを更新する            | [authenticatorClientPIN (0x06)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN) |
| async Task\<ResponseClientPIN_getPINToken> <br>**ClientPINgetPINTokenAsync**<br>(string pin)<br><br>async Task\<ResponseClientPIN_getPINToken> <br>**ClientPINgetPINTokenAsync**<br>(COSE_Key keyAgreement, byte[] pinHashEnc, byte[] sharedSecret) | PIN Tokenを取得する      | [authenticatorClientPIN (0x06)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN) |
| async Task\<ResponseReset><br>**ResetAsync()**               | FIDOキーをリセットする   | [authenticatorReset (0x07)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorReset) |



## HIDAuthenticatorConnector

- 継承元の`AuthenticatorConnector`に加えて以下のメソッド／イベントを実装しています。

| method/event                                                 | 機能                                    | 備考                                                         |
| ------------------------------------------------------------ | --------------------------------------- | ------------------------------------------------------------ |
| **HIDAuthenticatorConnector()**<br>**HIDAuthenticatorConnector**<br>(HidParam hidParam) | コンストラクタ                          |                                                              |
| bool <br>**IsConnected()**                                   | HID FIDOキーの接続チェック              | -                                                            |
| async Task\<bool><br>**WinkAsync()**                         | HID FIDOキーLEDを点滅する               | [CTAPHID_WINK (0x08)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-wink) |
| static List\<string><br>**GetAllHIDDeviceInfo()**            | 接続されているHIDデバイス情報を取得する | -                                                            |
| event EventHandler <br/>**KeepAlive**                        | UP,UVの操作Wait中に発生するイベント     | [CTAPHID_KEEPALIVE (0x3B)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-keepalive) |



## NFCAuthenticatorConnector

- 継承元の`AuthenticatorConnector`に加えて以下のメソッドを実装しています。

| method                          | 機能                       | 備考 |
| ------------------------------- | -------------------------- | ---- |
| **NFCAuthenticatorConnector()** | コンストラクタ             |      |
| bool <br>**IsConnected()**      | NFC FIDOキーの接続チェック | -    |



## BLEAuthenticatorConnector

- 継承元の`AuthenticatorConnector`に加えて以下のメソッド／イベントを実装しています。

| method/event                                                 | 機能                                     | 備考                                                         |
| ------------------------------------------------------------ | ---------------------------------------- | ------------------------------------------------------------ |
| **BLEAuthenticatorConnector()**                              | コンストラクタ                           |                                                              |
| async Task\<bool> <br>**ConnectAsync**<br>(ulong bluetoothAddress) | BLE FIDOキーと接続します                 | -                                                            |
| bool <br>**Disconnect()**                                    | BLE FIDOキーと切断します                 |                                                              |
| event EventHandler <br>**ConnectedDevice**                   | BLE FIDOキーと接続すると発生するイベント |                                                              |
| event EventHandler <br/>**DisconnectedDevice**               | BLE FIDOキーと切断すると発生するイベント |                                                              |
| event EventHandler <br/>**KeepAlive**                        | UP,UVの操作Wait中に発生するイベント      | [8.3.4.3.Command, Status, and Error constants](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ble-constants) |

