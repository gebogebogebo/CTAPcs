# Verifier

```csharp
public class Verifier
```

`Verifier`クラスを継承した`AttestationVerifier`クラス、`AssertionVerifier`クラスは主にサーバーサイドの役割を実装しています。



| method                                  |                                  |
| --------------------------------------- | -------------------------------- |
| static byte[] <br>**CreateChallenge()** | ランダムなチャレンジを生成します |





# AttestationVerifier

```csharp
public class AttestationVerifier:Verifier
```

`AuthenticatorConnector`クラス`MakeCredentialAsync()`メソッドでGETした`Attestation`を検証します。



| method                                                       |                                                              |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Result <br>**Verify**<br>(string rpid,byte[] challenge, Attestation att) | Attestationを検証します。<br>引数challengeは`MakeCredentialAsync()`に指定したものと同じものを指定してください。 |
| X509Certificate2 <br>**CreateSelfSignedCertificate**<br>(Result result,string rpName,string userName,TimeSpan expirationDate) | 自己署名した証明書を作成します。<br>引数resultはVerify()の結果を指定します。 |



## Result

```csharp
public class Result
```

Veriyの結果です。



| member                  |                   |
| ----------------------- | ----------------- |
| bool **IsSuccess**      | 検証結果          |
| byte[] **CredentialID** | クレデンシャルID  |
| string **PublicKeyPem** | 公開鍵（PEM形式） |





# AssertionVerifier

```csharp
public class AssertionVerifier : Verifier
```

`AuthenticatorConnector`クラス`GetAssertionAsync()`メソッドでGETした`Assertion`を検証します。



| method                                                       |                                                              |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Result <br>**Verify**<br>(string rpid,string publicKey, byte[] challenge,Assertion ass) | Assertionを検証します。<br>引数challengeは`GetAssertionAsync()`に指定したものと同じものを指定してください。 |



## Result

```csharp
public class Result
```

Veriyの結果です。



| member             |          |
| ------------------ | -------- |
| bool **IsSuccess** | 検証結果 |

