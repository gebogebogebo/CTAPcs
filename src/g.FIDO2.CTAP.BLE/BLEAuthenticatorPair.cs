using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Storage.Streams;
using g.FIDO2.CTAP;
using Windows.Devices.Enumeration;
using System.Collections.ObjectModel;

namespace g.FIDO2.CTAP.BLE
{
    //https://github.com/microsoft/Windows-universal-samples/blob/master/Samples/BluetoothLE/cs/Scenario1_Discovery.xaml.cs

    /// <summary>
    /// BLE Pairing / Bonding  Class
    /// </sumary>
    public class BLEAuthenticatorPair
    {
        
        public class GetDeviceEventArgs : EventArgs
        {
            /// <summary>
            /// IsPaired
            /// </summary>
            public bool IsPaired { get; set; }
            public Dictionary<string, object> Properties { get; set; }
        } 

        /// <summary>
        /// Find FIDO2 Device Event
        /// </summary>
        public event EventHandler<GetDeviceEventArgs> GetDevice;

        private DeviceWatcher _deviceWatcher;
        private DeviceInformation _lastDeviceInfo;
        private string _addressToPair;

        /// <summary>
        /// constructor
        /// </summary>
        public BLEAuthenticatorPair() { }

        /// <summary>
        /// Start Scan
        /// </summary>
        public bool Start(string bleAddress)
        {
            Logger.Log($"Start pairing for address: {bleAddress}");
            _addressToPair = bleAddress;

            // Additional properties we would like about the device.
            // Property strings are documented here https://msdn.microsoft.com/en-us/library/windows/desktop/ff521659(v=vs.85).aspx
            string[] requestedProperties = { "System.Devices.Aep.DeviceAddress", "System.Devices.Aep.IsConnected", "System.Devices.Aep.Bluetooth.Le.IsConnectable" };

            // BT_Code: Example showing paired and non-paired in a single query.
            string aqsAllBluetoothLEDevices = "(System.Devices.Aep.ProtocolId:=\"{bb7bb05e-5972-42b5-94fc-76eaa7084d49}\")";

            _deviceWatcher =
                    DeviceInformation.CreateWatcher(
                        aqsAllBluetoothLEDevices,
                        requestedProperties,
                        DeviceInformationKind.AssociationEndpoint);

            // Register event handlers before starting the watcher.
            _deviceWatcher.Added += DeviceWatcher_Added;
            _deviceWatcher.Updated += DeviceWatcher_Updated;
            _deviceWatcher.Removed += DeviceWatcher_Removed;
            _deviceWatcher.EnumerationCompleted += DeviceWatcher_EnumerationCompleted;
            _deviceWatcher.Stopped += DeviceWatcher_Stopped;

            // Start over with an empty collection.
            //KnownDevices.Clear();

            // Start the watcher. Active enumeration is limited to approximately 30 seconds.
            // This limits power usage and reduces interference with other Bluetooth activities.
            // To monitor for the presence of Bluetooth LE devices for an extended period,
            // use the BluetoothLEAdvertisementWatcher runtime class. See the BluetoothAdvertisement
            // sample for an example.
            _deviceWatcher.Start();

            return true;
        }

        /// <summary>
        /// Pair (bond) last found device
        /// </summary>
        public async Task<bool> Pair()
        {
            if (_lastDeviceInfo == null)
            {
                Logger.Log("Device not found to pair.");
                return false;
            }

            if (_lastDeviceInfo.Pairing.IsPaired)
            {
                Logger.Log("Device already paired.");
                return false;
            }

            //https://titanwolf.org/Network/Articles/Article?AID=d022a8d3-a516-4a83-ba43-b8d2e2c02de7#gsc.tab=0
            var customPairing = _lastDeviceInfo.Pairing.Custom;
            
            customPairing.PairingRequested += CustomPairing_PairingRequested;

            var pairingKind = DevicePairingKinds.ConfirmOnly;
            var protectionLevel = DevicePairingProtectionLevel.Encryption;
            var result = await customPairing.PairAsync(pairingKind, protectionLevel);

            customPairing.PairingRequested -= CustomPairing_PairingRequested;

            Logger.Log($"Pair status: {result.Status}.");

            return result.Status == DevicePairingResultStatus.Paired;
        }

        private void CustomPairing_PairingRequested(DeviceInformationCustomPairing sender, DevicePairingRequestedEventArgs args)
        {
            Logger.Log($"Accepting pairing request with PIN: {args.Pin}.");
            args.Accept();
        }

        /// <summary>
        /// UnPair (bond) last found device
        /// </summary>
        public async Task<bool> UnPair()
        {
            if (_lastDeviceInfo == null)
            {
                Logger.Log("Device not found to unpair.");
                return false;
            }

            if (!_lastDeviceInfo.Pairing.IsPaired)
            {
                Logger.Log("Device is not paired.");
                return false;
            }

            var result = await _lastDeviceInfo.Pairing.UnpairAsync();

            Logger.Log($"Unpair status: {result.Status}.");

            return result.Status == DeviceUnpairingResultStatus.Unpaired;
        }

        /// <summary>
        /// Stop Scan
        /// </summary>
        public bool Stop()
        {
            Logger.Log("Stopping ...");

            if (_deviceWatcher != null)
            {
                // Stop the watcher.
                _deviceWatcher.Stop();

                // Unregister the event handlers.
                _deviceWatcher.Added -= DeviceWatcher_Added;
                _deviceWatcher.Updated -= DeviceWatcher_Updated;
                _deviceWatcher.Removed -= DeviceWatcher_Removed;
                _deviceWatcher.EnumerationCompleted -= DeviceWatcher_EnumerationCompleted;
                _deviceWatcher.Stopped -= DeviceWatcher_Stopped;

                _deviceWatcher = null;

                Logger.Log("Stopped.");
            }

            return true;
        }

        private async void DeviceWatcher_Added(DeviceWatcher sender, DeviceInformation deviceInfo)
        {
            //Logger.Log($"Device Added with Id: {deviceInfo.Id}, Name: {deviceInfo.Name}, Kind: {deviceInfo.Kind}");
            //Could also check System.Devices.Aep.DeviceAddress:4a:d9:74:a3:29:4b
            if (deviceInfo.Id.Contains(_addressToPair))
            {
                Logger.Log($"Got matching DeviceInfo for : {deviceInfo.Id}, Name: {deviceInfo.Name}, Kind: {deviceInfo.Kind}");
                Stop();

                //Keep for future pairing
                _lastDeviceInfo = deviceInfo;

                if (GetDevice != null)
                {
                    var args = new GetDeviceEventArgs();

                    if (deviceInfo.Pairing.IsPaired) args.IsPaired = true;
                    args.Properties = new Dictionary<string, object>();

                    foreach (var de in deviceInfo.Properties) args.Properties.Add(de.Key, de.Value);

                    GetDevice.Invoke(this, args);
                }
            }
        }

        private async void DeviceWatcher_Updated(DeviceWatcher sender, DeviceInformationUpdate deviceInfoUpdate)
        {
            //Logger.Log($"Device Updated with Id: {deviceInfoUpdate.Id}");
        }

        private async void DeviceWatcher_Removed(DeviceWatcher sender, DeviceInformationUpdate deviceInfoUpdate)
        {
            //Logger.Log($"Device Removed with Id: {deviceInfoUpdate.Id}");
        }

        private async void DeviceWatcher_EnumerationCompleted(DeviceWatcher sender, object e)
        {
            Logger.Log($"Enumeration completed");
        }

        private async void DeviceWatcher_Stopped(DeviceWatcher sender, object e)
        {
            Logger.Log($"Watcher stoppped");
        }
    }
}
