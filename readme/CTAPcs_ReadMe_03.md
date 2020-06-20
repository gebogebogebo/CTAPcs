# BLEAuthenticatorScanner Class

```csharp
public class BLEAuthenticatorScanner
```

BLEAuthenticatorScanner は BLEアドバタイズパケットをスキャンするクラスです。

**Start()**でスキャンを開始し、発見すると**FindDevice**イベントが発生します。

**Stop()でスキャン停止します。**

FindDeviceイベントで取得した**BluetoothAddress**をBLEAuthenticatorConnector.**ConnectAsync()**に指定してデバイスに接続します。



| member                               |                               |
| ------------------------------------ | ----------------------------- |
| bool **IsStarted**                   | スキャンStartしているかどうか |
| int **SamplingIntervalMilliseconds** | スキャン間隔（ミリ秒）        |



| method               | 機能                                                      |
| -------------------- | --------------------------------------------------------- |
| bool <br>**Start()** | FIDOデバイスのBLEアドバタイズパケットのスキャンを開始する |
| bool <br/>**Stop()** | アドバタイズパケットのスキャンを停止する                  |



| event                                                     | 説明                                                         |
| --------------------------------------------------------- | ------------------------------------------------------------ |
| event EventHandler<FindDeviceEventArgs><br>**FindDevice** | FIDOデバイス発見イベント<br>**FindDeviceEventArgs**に発見したデバイスの情報が格納される |



## FindDeviceEventArgs Class

| member                      |                                                              |
| --------------------------- | ------------------------------------------------------------ |
| ulong **BluetoothAddress**  | BLEアドレス<br>BLEAuthenticatorConnector.**ConnectAsync()**に指定する |
| ushort **CompanyId**        | アドバタイズパケットに格納されているCompanyId                |
| byte[] **ManufacturerData** | アドバタイズパケットに格納されているManufacturerData         |

