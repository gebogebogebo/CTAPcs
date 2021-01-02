using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Storage.Streams;
using g.FIDO2.CTAP;

namespace g.FIDO2.CTAP.BLE
{

    /// <summary>
    /// BLE Advertisement packet Scanner Class
    /// </summary>
    public class BLEAuthenticatorScanner
    {
        /// <summary>
        /// Scan Start Flag
        /// </summary>
        public bool IsStarted { get; private set; } = false;

        /// <summary>
        /// SamplingIntervalMilliseconds
        /// </summary>
        public int SamplingIntervalMilliseconds { get; set; } = 1000;

        /// <summary>
        /// FindDevice EventArgs Class
        /// </summary>
        public class FindDeviceEventArgs : EventArgs
        {

            /// <summary>
            /// BluetoothAddress 8byte
            /// </summary>
            public ulong BluetoothAddress { get; private set; }

            /// <summary>
            /// CompanyId 2byte
            /// </summary>
            public ushort CompanyId { get; private set; }

            /// <summary>
            /// ManufacturerData 
            /// </summary>
            public byte[] ManufacturerData { get; private set; }

            /// <summary>
            /// AdvertisementType 
            /// </summary
            public string AdvertisementType { get; private set; }

            /// <summary>
            /// LocalName 
            /// </summary
            public string LocalName { get; private set; }

            /// <summary>
            /// LocalName 
            /// </summary
            public bool HasManufacturerData { get; private set; }

            /// <summary>
            /// LocalName 
            /// </summary
            public List<Guid> ServiceUuids { get; private set; }

            internal FindDeviceEventArgs(BluetoothLEAdvertisementReceivedEventArgs args)
            {
                CompanyId = 0;
                ManufacturerData = new byte[0];
                AdvertisementType = args.AdvertisementType.ToString();
                LocalName = args.Advertisement.LocalName;
                ServiceUuids = new List<Guid>(args.Advertisement.ServiceUuids);

                this.BluetoothAddress = args.BluetoothAddress;
                foreach (var mdata in args.Advertisement.ManufacturerData.ToList()) {
                    HasManufacturerData = true;

                    this.CompanyId = mdata.CompanyId;
                    var data = new byte[mdata.Data.Length];
                    using (var reader = DataReader.FromBuffer(mdata.Data)) {
                        reader.ReadBytes(data);
                        this.ManufacturerData = data.ToArray();
                    }
                }
            }
        }

        /// <summary>
        /// Find FIDO2 Device Event
        /// </summary>
        public event EventHandler<FindDeviceEventArgs> FindDevice;

        /// <summary>
        /// constructor
        /// </summary>
        public BLEAuthenticatorScanner() { }

        /// <summary>
        /// Start Scan
        /// </summary>
        public bool Start()
        {
            Logger.Log("Start");

            //this.advWatcher = new BluetoothLEAdvertisementWatcher();
            
            //Experiment with using a filter directly in the watcher to try emulate Windows more closely
            var filter = new BluetoothLEAdvertisementFilter();
            filter.Advertisement.ServiceUuids.Add(Common.Gatt_Service_FIDO_GUID);

            this.advWatcher = new BluetoothLEAdvertisementWatcher(filter);

            // インターバルがゼロのままだと、CPU負荷が高くなりますので、適切な間隔(SDK サンプルでは 1秒)に指定しないと、アプリの動作に支障をきたすことになります。
            // If the interval remains zero, the CPU load will be high, so if you do not specify an appropriate interval (1 second in the SDK sample),
            // it will interfere with the operation of the application.
            this.advWatcher.SignalStrengthFilter.SamplingInterval = TimeSpan.FromMilliseconds(SamplingIntervalMilliseconds);

            // rssi >= -60のときスキャンする
            //this.advWatcher.SignalStrengthFilter.InRangeThresholdInDBm = -60;

            // パッシブスキャン/アクティブスキャン
            // スキャン応答のアドバタイズを併せて受信する場合＝BluetoothLEScanningMode.Active
            // ActiveにするとBluetoothLEAdvertisementType.ScanResponseが取れるようになる。（スキャンレスポンスとは追加情報のこと）
            // ※電力消費量が大きくなり、またバックグラウンド モードでは使用できなくなるらしい

            // Passive scan / active scan
            // When receiving the advertisement of the scan response together = BluetoothLEScanningMode.Active
            // When set to Active, BluetoothLEAdvertisementType.ScanResponse can be obtained. (Scan response is additional information)
            // * It seems that power consumption will increase and it will not be available in background mode.

            //this.advWatcher.ScanningMode = BluetoothLEScanningMode.Active;
            this.advWatcher.ScanningMode = BluetoothLEScanningMode.Passive;

            // アドバタイズパケットの受信イベント | Advertisement packet reception event
            //this.advWatcher.Received += this.watcherReceived;
            this.advWatcher.Received += filteredWatcherReceived;

            // スキャン開始 | Start scanning
            this.advWatcher.Start();

            IsStarted = true;

            return true;
        }

        /// <summary>
        /// Stop Scan
        /// </summary>
        public bool Stop()
        {
            Logger.Log("Stop");
            if (this.advWatcher == null) {
                return (false);
            }
            this.advWatcher.Stop();
            IsStarted = false;
            return (true);
        }

        // private
        private BluetoothLEAdvertisementWatcher advWatcher;

        private void watcherReceived(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            bool find = false;
            {
                // search FIDO service
                if (args.Advertisement.ServiceUuids.Contains(Common.Gatt_Service_FIDO_GUID)) {
                    /*
                    foreach(var d in args.Advertisement.DataSections) {
                        // Local Name
                        if( d.DataType == 0x09) {
                            byte[] readBytes = new byte[d.Data.Length];
                            using (DataReader reader = DataReader.FromBuffer(d.Data)) {
                                reader.ReadBytes(readBytes);
                                //ASCII エンコード | ASCII encoding
                                string text = System.Text.Encoding.ASCII.GetString(readBytes);
                            }
                        }
                    }
                    */
                    find = true;
                    Logger.Log("Scan FIDO Device");
                }
            }

            if (find) {
                try {
                    // Event
                    var e = new FindDeviceEventArgs(args);
                    FindDevice?.Invoke(this, e);
                } catch (Exception ex) {
                    Logger.Err($"Exception...{ex.Message})");
                }
            }
            return;
        }

        private void filteredWatcherReceived(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            try
            {
                // Event
                var e = new FindDeviceEventArgs(args);
                FindDevice?.Invoke(this, e);

                
            }
            catch (Exception ex)
            {
                Logger.Err($"Exception...{ex.Message})");
            }
        }
    }
}
