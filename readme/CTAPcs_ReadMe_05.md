

# HidParam

```csharp
public class CTAPCommandMakeCredentialParam
```

HidParam は`HIDAuthenticatorConnector`クラスのコンストラクタに指定します。

HidParamで検索対象のHIDタイプのFIDOキーを指定します。

HIDデバイスはベンダーID、プロダクトID、DescriptionをもっておりHIDタイプのFIDOキーも製品毎に異なっています。

`HIDAuthenticatorConnector`クラスの`GetAllHIDDeviceInfo()`でベンダーID、プロダクトIDを調査することもできますが、とりあえず、**GetDefaultParams()** で主要なFIDOキーのHidParmを作成することができます。あるいは、`HIDAuthenticatorConnector`のコンストラクタにHidParamを指定しなければ **GetDefaultParams()** が適用されます。



| member |      |
| ------------------------------ | ---- |
| int **VendorId**     | 検索対象のベンダーID |
| int **ProductId**    | 検索対象のプロダクトID。0の場合は全てのプロダクトID |
| string **Something** | 検索対象のDescription                               |



| method                                            | 機能                              | 備考                                                         |
| ------------------------------------------------- | --------------------------------- | ------------------------------------------------------------ |
| static List\<HidParam> <br>**GetDefaultParams()** | 主要なFIDOキーのHidParmを作成する | 詳細は[HIDParam.cs](https://github.com/gebogebogebo/CTAPcs/blob/master/src/g.FIDO2.CTAP.HID/HIDParam.cs)参照 |





# CTAPCommandMakeCredentialParam

```csharp
public class CTAPCommandMakeCredentialParam
```

CTAPCommandMakeCredentialParamは`AuthenticatorConnector`クラス`MakeCredentialAsync`メソッドの引数です。



| member                                                       |                                                              |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| string **RpId**<br/>string **RpName**<br/>byte[] **UserId**<br/>string **UserName**<br/>string **UserDisplayName**<br/>bool **Option_rk**<br/>bool **Option_uv** | [5.1. authenticatorMakeCredential (0x01)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential) |



| method                                                       | 機能           | 備考                             |
| ------------------------------------------------------------ | -------------- | -------------------------------- |
| public <br>**CTAPCommandMakeCredentialParam**<br>(string rpid, byte[] challenge,byte[] userid) | コンストラクタ | 引数はコマンド実行に必須のメンバ |





# CTAPCommandGetAssertionParam

```csharp
public class CTAPCommandGetAssertionParam
```

CTAPCommandGetAssertionParamは`AuthenticatorConnector`クラス`CTAPCommandGetAssertion`メソッドの引数です。



| member                                                       |                                                              |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| string **RpId**<br/>byte[] **ClientDataHash**<br/>byte[] **AllowList_CredentialId**<br/>bool **Option_up**<br/>bool **Option_uv** | [5.2. authenticatorGetAssertion (0x02)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion) |



| method                                                       | 機能           | 備考                             |
| ------------------------------------------------------------ | -------------- | -------------------------------- |
| **CTAPCommandGetAssertionParam**<br>(string rpid,byte[] challenge,byte[] credentialid=null) | コンストラクタ | 引数はコマンド実行に必須のメンバ |





# Serializer

```csharp
public class Serializer
```

`Attestation`クラス、`Assertion`クラスをシリアライズ、デシリアライズします。



| method                                                       |                                   |      |
| ------------------------------------------------------------ | --------------------------------- | ---- |
| static byte[]<br>**Serialize**<br>(Attestation att)          | Attestationをシリアライズします   |      |
| static Attestation <br>**DeserializeAttestation**<br>(byte[] byteData) | Attestationをデシリアライズします |      |
| static byte[] <br>**Serialize**<br>(Assertion ass)           | Assertionをシリアライズします     |      |
| static Assertion <br>**DeserializeAssertion**<br>(byte[] byteData) | Assertionをデシリアライズします   |      |



