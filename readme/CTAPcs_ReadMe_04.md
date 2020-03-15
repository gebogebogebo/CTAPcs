# CTAPResponse Class

応答は`CTAPResponse`を継承した以下のクラスです。

- `CTAPResponseGetInfo`
- `CTAPResponseMakeCredential`
- `CTAPResponseGetAssertion`



## CTAPResponse

| member |      |
| ------------------------------ | ---- |
| byte **Status**                | [6.3. Status codes](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#error-responses) |
| string **StatusMsg**           | ステータスメッセージ |
| string **SendPayloadJson** | 送信ペイロード |
| string **ResponsePayloadJson** | 受信ペイロード |



## CTAPResponseGetInfo

| member |      |
| ------------------------------ | ---- |
| string[] **Versions**<br/>string[] **Extensions**<br/>byte[] **Aaguid**<br/>OptionFlag **Option_rk**<br/>OptionFlag **Option_up**<br/>OptionFlag **Option_plat**<br/>OptionFlag **Option_clientPin**<br/>OptionFlag **Option_uv**<br/>int **MaxMsgSize**<br/>int[] **PinProtocols** | [5.4. authenticatorGetInfo (0x04)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo) |



## CTAPResponseMakeCredential

| member                      |                                                              |
| --------------------------- | ------------------------------------------------------------ |
| Attestation **Attestation** | [6.4. Attestation](https://www.w3.org/TR/webauthn/#sctn-attestation) |



## CTAPResponseGetAssertion

| member                  |                                                              |
| ----------------------- | ------------------------------------------------------------ |
| Assertion **Assertion** | [5.2. authenticatorGetAssertion (0x02)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion) |