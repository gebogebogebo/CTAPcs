using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using HidLibrary;

namespace g.FIDO2.CTAP.HID
{
    internal class CTAPHID : IDisposable
	{
        public event EventHandler KeepAlive;

        public int ReceiveResponseTotalTimeoutMs = 0;
        public bool isReceiveResponseTotalTimeout = false;

        private const byte CTAP_FRAME_INIT = 0x80;
		private const int CTAP_RPT_SIZE = 64;
		private const byte STAT_ERR = 0xbf;

        // CTAP Command
		private const byte CTAPHID_INIT = 0x06;
        private const byte CTAPHID_CBOR = 0x10;
        //This command code is used in response messages only.
        private const byte CTAPHID_ERROR = 0x3F;
        private const byte CTAPHID_KEEPALIVE = 0x3B;
        //private const byte CTAPHID_KEEPALIVE_STATUS_PROCESSING = 1;     // The authenticator is still processing the current request.
        //private const byte CTAPHID_KEEPALIVE_STATUS_UPNEEDED = 2;       // The authenticator is waiting for user presence.

        private const uint BROADCAST_CID = 0xffffffff;

		private const int CallTimeoutMs = 1000;

		private readonly Random random = new Random();

		private readonly IHidDevice hidDevice;
		private byte[] cid;

		protected CTAPHID(IHidDevice hidDevice)
		{
			this.hidDevice = hidDevice;
			this.cid = BitConverter.GetBytes(BROADCAST_CID);
		}

		public static async Task<CTAPHID> OpenAsync(IHidDevice hidDevice)
		{
			var device = new CTAPHID(hidDevice);
			await device.InitAsync();
			return device;
		}

		protected async Task InitAsync()
		{
			var nonce = new byte[8];
			random.NextBytes(nonce);
			var response = await CallAsync(CTAPHID_INIT, nonce);

			while (!response.Take(8).SequenceEqual(nonce))
			{
				await Task.Delay(100);
				response = await CallAsync(CTAPHID_INIT, nonce);
			}

			this.cid = response.Skip(8).Take(4).ToArray();

		}

        public async Task<byte[]> CborAsync(byte[] command)
        {
            return await CallAsync(CTAPHID_CBOR, command);
        }

        private async Task<byte[]> CallAsync(byte command, byte[] data = null)
		{
			await SendCommandAsync(command, data);
			return await ReceiveResponseAsync(command);
		}

		private async Task SendCommandAsync(byte command, byte[] data = null)
		{
			if (data == null)
			{
				data = new byte[0];
			}

			var reportSize = CTAP_RPT_SIZE;

			var size = data.Length;
			var bc_l = (byte)(size & 0xff);
			var bc_h = (byte)(size >> 8 & 0xff);
			var payloadData = data.Take(reportSize - 7).ToArray();

            System.Diagnostics.Debug.WriteLine($"Payload data: {BitConverter.ToString(payloadData)}");

            {
                var packet = new List<byte>();
                packet.AddRange(cid);
                packet.Add((byte)(CTAP_FRAME_INIT | command));
                packet.Add(bc_h);
                packet.Add(bc_l);
                packet.AddRange(payloadData);
                while (packet.Count < reportSize) {
                    packet.Add(0x00);
                }
                var report = hidDevice.CreateReport();
                report.Data = packet.ToArray();
                var sendst = await hidDevice.WriteReportAsync(report, CallTimeoutMs);
                System.Diagnostics.Debug.WriteLine($"send Packet({sendst}): ({report.Data.Length}):{BitConverter.ToString(report.Data)}");

            }


            var remainingData = data.Skip(reportSize - 7).ToArray();
			var seq = 0;
			while (remainingData.Length > 0)
			{
				payloadData = remainingData.Take(reportSize - 5).ToArray();

                var packet = new List<byte>();
                packet.AddRange(cid);
                packet.Add((byte)(0x7f & seq));
                packet.AddRange(payloadData);
                while (packet.Count < reportSize) {
                    packet.Add(0x00);
                }
                var report = hidDevice.CreateReport();
                report.Data = packet.ToArray();

				if (!await hidDevice.WriteReportAsync(report, CallTimeoutMs))
				{
					throw new Exception("Error writing to device");
				}
                System.Diagnostics.Debug.WriteLine($"send Packet: ({report.Data.Length}):{BitConverter.ToString(report.Data)}");

                remainingData = remainingData.Skip(reportSize - 5).ToArray();
				seq++;
			}
		}

		private async Task<byte[]> ReceiveResponseAsync(byte command)
		{
			var reportSize = CTAP_RPT_SIZE;

            HidReport report = null;
            var resp = Encoding.ASCII.GetBytes(".");

            int loop_n = 999;
            int keepalivesleepms = 100;
            bool isGet = false;

            if ( this.ReceiveResponseTotalTimeoutMs > 0 && keepalivesleepms > 0 ) {
                loop_n = this.ReceiveResponseTotalTimeoutMs / keepalivesleepms;
            }

            bool eventKeepAlive = false;
            for (int intIc = 0 ;intIc < loop_n ;intIc++ ) {
                report = await hidDevice.ReadReportAsync(CallTimeoutMs);

                if (report.ReadStatus != HidDeviceData.ReadStatus.Success) {
                    throw new Exception("Error reading from device");
                }

                System.Diagnostics.Debug.WriteLine($"recv Packet: ({report.Data.Length}):{BitConverter.ToString(report.Data)}");

                resp = report.Data;

                // error check
                if( resp[4] == (byte)(CTAP_FRAME_INIT | CTAPHID_ERROR)) {
                    throw new Exception("Error in response header");
                } else if(resp[4] == (byte)(CTAP_FRAME_INIT | CTAPHID_KEEPALIVE)) {
                    System.Diagnostics.Debug.WriteLine("keep alive");

                    // event 1time
                    if (eventKeepAlive == false) {
                        KeepAlive?.BeginInvoke(this, EventArgs.Empty, null, null);
                        eventKeepAlive = true;
                    }
                    await Task.Delay(keepalivesleepms);
                    continue;
                }
                isGet = true;
                break;
            }
            if(isGet == false) {
                // timeout
                System.Diagnostics.Debug.WriteLine("timeout");
                isReceiveResponseTotalTimeout = true;
                return null;
            }

			var dataLength = (report.Data[5] << 8) + report.Data[6];
            var payloadData = report.Data.Skip(7).Take(Math.Min(dataLength, reportSize)).ToList();

            dataLength -= (int)payloadData.Count;

			var seq = 0;
			while (dataLength > 0)
			{
				report = await hidDevice.ReadReportAsync(CallTimeoutMs);

				if (report.ReadStatus != HidDeviceData.ReadStatus.Success)
				{
					throw new Exception("Error reading from device");
				}

				if (!report.Data.Take(4).SequenceEqual(cid))
				{
					throw new Exception("Wrong CID from device");
				}
				if (report.Data[4] != (byte)(seq & 0x7f))
				{
					throw new Exception("Wrong SEQ from device");
				}
				seq++;
				var packetData = report.Data.Skip(5).Take(Math.Min(dataLength, reportSize)).ToList();

				dataLength -= packetData.Count;

                payloadData.AddRange(packetData);
			}

			var result = payloadData.ToArray();
            return result;
		}

		public void Dispose()
		{
			hidDevice.CloseDevice();
		}

        public class SendCommandandResponseResult
        {
            public byte[] responseData { get; set; }
            public bool isTimeout { get; set; }
            public SendCommandandResponseResult()
            {
                responseData = null;
                isTimeout = false;
            }
        }

        public static async Task<SendCommandandResponseResult> SendCommandandResponse(List<HidParam> hidParams, byte[] send,int timeoutms,EventHandler keepalive)
        {
            var result = new SendCommandandResponseResult();
            IHidDevice hidDevice = null;

            try {
                hidDevice = CTAPHID.find(hidParams);
                if (hidDevice == null) {
                    return null;
                }
                using (var openedDevice = await CTAPHID.OpenAsync(hidDevice)) {
                    openedDevice.ReceiveResponseTotalTimeoutMs = timeoutms;
                    openedDevice.KeepAlive += keepalive;
                    result.responseData = await openedDevice.CborAsync(send);
                    result.isTimeout = openedDevice.isReceiveResponseTotalTimeout;
                }

            } catch (Exception) {

            } finally {
                if (hidDevice != null) {
                    hidDevice.Dispose();
                }
            }
            return (result);
        }

        public static HidDevice find(List<HidParam> hidparams)
        {
            HidDevice device = null;
            foreach (var hidparam in hidparams) {
                if (hidparam.ProductId == 0x00) {
                    device = HidDevices.Enumerate(hidparam.VendorId).OrderBy(x=>x.DevicePath).FirstOrDefault();
                    if (device != null) {
                        break;
                    }
                } else {
                    var devs = HidDevices.Enumerate(hidparam.VendorId, hidparam.ProductId).OrderBy(x => x.DevicePath);
                    foreach( var dev in devs) {
                        if(string.IsNullOrEmpty(hidparam.Something)) {
                            device = dev;
                            break;
                        }
                        if( dev.DevicePath.IndexOf(hidparam.Something, StringComparison.OrdinalIgnoreCase) >= 0 ) {
                            device = dev;
                            break;
                        }
                    }

                    if (device != null) {
                        break;
                    }
                }
            }
            return (device);
        }


    }
}
