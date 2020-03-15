# AuthenticatorConnector - Method

## GetInfoAsync

```
public async Task<ResponseGetInfo> GetInfoAsync()
```


- 機能
  - **authenticatorGetInfo**コマンドを実行します。
- 戻り値
  - [ResponseGetInfo]()
  - 応答の詳細は[5.4. authenticatorGetInfo (0x04)](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo)を参照してください。
- 説明
  - FIDOキーの情報をGETします。

```cs:sample
using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using g.FIDO2.CTAP.HID;

namespace HIDTest01
{
    public partial class MainWindow : Window
    {

        HIDAuthenticatorConnector con;

        public MainWindow()
        {
            InitializeComponent();
            con = new HIDAuthenticatorConnector();
        }

        private async void ButtonGetInfo_Click(object sender, RoutedEventArgs e)
        {
            addLog("<GetInfo>");
            var res = await con.GetInfoAsync();
            LogResponse(res.DeviceStatus,res.CTAPResponse);
            if(res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Unauthorized) {
                addLog("Excute Administrator ?");
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.NotConnected) {
                addLog("FIDO Key Not Connected");
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok) {
                if (res.CTAPResponse.Status == 0) {
                    addLog("Get CTAP Response");
                }
            }
        }
    }
}
```



## MakeCredentialAsync

```
public async Task<ResponseMakeCredential> MakeCredentialAsync(CTAPCommandMakeCredentialParam param, string pin)
```

- 機能
  - **authenticatorMakeCredential**コマンドを実行し応答を取得します。
- 引数
  - [CTAPCommandMakeCredentialParam]() param
    - 詳細は[5.1. authenticatorMakeCredential (0x01)]()を参照してください。
  - string pin 
    - FIDOキーのPINを指定します。省略する場合は空文字を指定してください。
- 戻り値
  - [ResponseMakeCredential]()
  - 応答の詳細は[5.1. authenticatorMakeCredential (0x01)]()を参照してください。
- 説明
  - FIDOキーへクレデンシャルを登録し、登録結果（Attestation）をGETします。
  - UPまたはUVの入力待ち状態になると、**OnKeepAlive**イベントが発生します。

```c#:sample
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using g.FIDO2.CTAP.HID;

namespace HIDTest01
{
    public partial class MainWindow : Window
    {
        private void OnKeepAlive(object sender, EventArgs e)
        {
            addLog($"<OnKeppAlive>");
            addLog($"- touch authenticator!");
        }

        HIDAuthenticatorConnector con;

        public MainWindow()
        {
            InitializeComponent();
            con = new HIDAuthenticatorConnector();
            con.KeepAlive += OnKeepAlive;
        }

        private async void ButtonMakeCredential_Click(object sender, RoutedEventArgs e)
        {
            addLog("<makeCredential>");

            var rpid = "test.com";
            var challenge = System.Text.Encoding.ASCII.GetBytes("this is challenge");

            var param = new g.FIDO2.CTAP.CTAPCommandMakeCredentialParam(rpid,challenge);
            param.RpName = "test name";
            param.UserId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            param.UserName = "testUserName";
            param.UserDisplayName = "testUserDisplayName";
            param.Option_rk = false;
            param.Option_uv = true;

            string pin = "1234";

            var res = await con.MakeCredentialAsync(param, pin);
            LogResponse(res.DeviceStatus,res.CTAPResponse);

            if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.NotConnected) {
                addLog("FIDO Key Not Connected");
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Timeout) {
                addLog("UP or UV timeout");
                return;
            } else if (res.DeviceStatus == g.FIDO2.CTAP.DeviceStatus.Ok) {
                if (res.CTAPResponse.Status == 0) {
                    if (res?.CTAPResponse?.Attestation != null) {
                        addLog("Get CTAP Response");
                        var att = g.FIDO2.Serializer.Serialize(res.CTAPResponse.Attestation);
                        // send att to Server

                        var creid = g.FIDO2.Common.BytesToHexString(res.CTAPResponse.Attestation.CredentialId);
                        addLog($"- CredentialID = {creid}\r\n");
                    }
                }
            }

        }
    }
}
```

