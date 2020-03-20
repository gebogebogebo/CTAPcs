# CTAPcsについて
- [FIDO Alliance Client to Authenticator Protocol (CTAP)Proposed Standard, January 30, 2019](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)を実装したDllです。

- HID/NFC/BLEのAuthenticatorとのCTAPプロトコル通信、チャレンジ生成、Attestation、AssertionのVerifyを実装しています。

- WPFアプリケーションで利用するDllとして作成しています。

  


# 開発環境
- Windows10 1903,1909
- Visual Studio 2017
- .Net Framework 4.6.1
- 以下のOSSを使っています
    - System.ValueTuple 4.5.0
    - Microsoft.Windows.SDK.Contracts v10.0.18362.2005
    - PeterO.Cbor 4.1.0
    - hidlibrary v3.3.24
    - BouncyCastle.Crypto 1.8.5




# Dll構成

- g.FIDO2.CTAP.HID.dll
    - HIDタイプのFIDOキーを利用するための`HIDAuthenticatorConnector`クラスを実装しています。
- g.FIDO2.CTAP.NFC.dll
    - NFCタイプのFIDOキーを利用するための`NFCAuthenticatorConnector`クラスを実装しています。
- g.FIDO2.CTAP.BLE.dll
    - BLEタイプのFIDOキーを利用するための`BLEAuthenticatorConnector`クラス、`BLEAuthenticatorScanner`クラスを実装しています。
- g.FIDO2.Util.dll
    - FIDOサーバー側で利用する`AttestationVerifier`クラス、`AssertionVerifier`クラスを実装しています。
- g.FIDO2.dll
    - 共通コンポーネント。
- g.FIDO2.CTAP.dll
    - 共通コンポーネント。




# ビルド方法

- examplesフォルダのexamples.slnでDll、サンプルプログラム全てをビルドすることができます。



# サンプルプロジェクト

- HIDTest01  
    - HIDタイプのFIDOキーを利用するサンプルです。
- NFCTest01
    - NFCタイプのFIDOキーを利用するサンプルです。
- BLETest01  
    - BLEタイプのFIDOキーを利用するサンプルです。
- xClient 
    - クライアントサイドアプリケーションサンプルです。
- xServer
    - サーバーサイドアプリケーションサンプルです。
    
    


# プロジェクトを新規作成する方法
- WPFアプリ(.NET Framwwork)を新規作成します。
- .Net Framework 4.6.1が推奨ですが、それ以外でも動くかと思います。
- FIDOキーを利用する場合、exeを管理者権限で実行する必要があります。
    - プロジェクトにアプリケーションマニフェストファイルを追加し、requestedExecutionLevelのlevelを**requireAdministrator**に変更してください。この設定で管理者権限でアプリが実行されるようになります。
- HIDタイプのFIDOキーを利用する場合、以下の参照を追加してください。
    - `g.FIDO2.CTAP.HID.dll`
    - `g.FIDO2.CTAP.dll`
    - `g.FIDO2.dll`
- NFCタイプのFIDOキーを利用する場合、以下の参照を追加してください。 
    - `g.FIDO2.CTAP.NFC.dll`
    - `g.FIDO2.CTAP.dll`
    - `g.FIDO2.dll`
- BLEタイプのFIDOキーを利用する場合、以下の参照を追加してください。
    - `g.FIDO2.CTAP.BLE.dll`
    - `g.FIDO2.CTAP.dll`
    - `g.FIDO2.dll`
- FIDOサーバーの機能（Attestation、AssertionのVerify）を利用する場合、以下の参照を追加してください。
    - `g.FIDO2.Util.dll`
    - `g.FIDO2.dll`


