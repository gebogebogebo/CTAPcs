# APIリファレンス

FIDOキーと通信するクラスは`AuthenticatorConnector`を継承した以下のクラスです。

- `HIDAuthenticatorConnector`
  - CTAPのHIDインタフェースを実装しています。HIDタイプのFIDOキーと通信します。

- `NFCAuthenticatorConnector`
  - CTAPのNFCインタフェースを実装しています。NFCタイプのFIDOキーと通信します。

- `BLEAuthenticatorConnector`
  - CTAPのBLEインタフェースを実装しています。BLEタイプのFIDOキーと通信します。



## AuthenticatorConnector

以下のメソッドを実装しています。

| メソッド                      | 機能                     | 対応するCTAPコマンド                                         |
| ----------------------------- | ------------------------ | ------------------------------------------------------------ |
| GetInfoAsync                  | FIDOキーの情報を取得する | [authenticatorGetInfo (0x04)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo) |
| MakeCredentialAsync           | クレデンシャルの登録     | [authenticatorMakeCredential(0x01)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential) |
| GetAssertionAsync             | 認証                     | [authenticatorGetAssertion (0x02)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion) |
| GetNextAssertionAsync         | 認証                     | [authenticatorGetNextAssertion (0x08)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetNextAssertion) |
| ClientPINgetRetriesAsync      | PINリトライ回数の取得    | [authenticatorGetInfo (0x04)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo) |
| ClientPINgetKeyAgreementAsync | Key Agreementを取得する  | [authenticatorClientPIN (0x06)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN) |
| ClientPINsetPINAsync          | 初期PINを設定する        | [authenticatorClientPIN (0x06)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN) |
| ClientPINchangePINAsync       | PINを更新する            | [authenticatorClientPIN (0x06)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN) |
| ClientPINgetPINTokenAsync     | PIN Tokenを取得する      | [authenticatorClientPIN (0x06)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN) |
| ResetAsync                    | FIDOキーをリセットする   | [authenticatorReset (0x07)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorReset) |



## HIDAuthenticatorConnector

- 継承元の`AuthenticatorConnector`に加えて以下のメソッド／イベントを実装しています。

| メソッド/イベント   | 機能                                    | 備考                                                         |
| ------------------- | --------------------------------------- | ------------------------------------------------------------ |
| IsConnected         | FIDOキーの接続チェック                  | -                                                            |
| Wink                | FIDOキーLEDを点滅する                   | [CTAPHID_WINK (0x08)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-wink) |
| GetAllHIDDeviceInfo | 接続されているHIDデバイス情報を取得する | -                                                            |
| KeepAlive           | UP,UVの操作Wait中に発生するイベント     | [CTAPHID_KEEPALIVE (0x3B)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-hid-keepalive) |