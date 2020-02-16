using System;
using System.Runtime.InteropServices;

namespace g.FIDO2.CTAP.NFC
{
    internal static class SCardAPI {
		private const string FileName = "winscard.dll";
		public const uint SCARD_SCOPE_USER = 0x0000;
		public const uint SCARD_SCOPE_SYSTEM = 0x0002;
		public const uint SCARD_SHARE_EXCLUSIVE = 0x00000002;
		public const uint SCARD_SHARE_SHARED = 0x00000002;
		public const uint SCARD_SHARE_DIRECT = 0x00000003;
		public const uint SCARD_PROTOCOL_T0 = 0x0001;
		public const uint SCARD_PROTOCOL_T1 = 0x0002;
		public const uint SCARD_LEAVE_CARD   = 0x0000;
		public const uint SCARD_RESET_CARD   = 0x0001;
		public const uint SCARD_UNPOWER_CARD = 0x0002;
		public const uint SCARD_EJECT_CARD   = 0x0003;

        // - Smart Card Database Query Functions
        // https://msdn.microsoft.com/ja-jp/library/windows/desktop/aa379793(v=vs.85).aspx"
        [DllImport(FileName, EntryPoint = "SCardListReadersW", CharSet = CharSet.Unicode)]
		public static extern SCardResult SCardListReaders([In]IntPtr hContext, [In, Optional]Char[] mszGroups, [Out]Char[] mszReaders, [In, Out]ref UInt32 pcchReaders);

        // - Resource Manager Context Functions
		// https://msdn.microsoft.com/ja-jp/library/windows/desktop/aa379479(v=vs.85).aspx
		[DllImport(FileName)]
		public static extern SCardResult SCardEstablishContext([In]UInt32 dwScope, [In]IntPtr pvReserved1, [In]IntPtr pvReserved2, [Out]out IntPtr phContext);

		// https://msdn.microsoft.com/ja-jp/library/windows/desktop/aa379798(v=vs.85).aspx
		[DllImport(FileName)]
		public static extern SCardResult SCardReleaseContext([In]IntPtr hContext);

        // - Smart Card and Reader Access Functions
        // https://msdn.microsoft.com/ja-jp/library/windows/desktop/aa379473(v=vs.85).aspx
        [DllImport(FileName, EntryPoint = "SCardConnectW", CharSet = CharSet.Unicode)]
		public static extern SCardResult SCardConnect([In]IntPtr hContext, [In]string szReader, [In]UInt32 dwShareMode, [In]UInt32 dwPreferredProtocols, [Out]out IntPtr phCard, [Out]out UInt32 pdwActiveProtocol);

		[DllImport(FileName)]
		public static extern SCardResult SCardDisconnect([In]IntPtr hCard, [In]UInt32 dwDisposition);

		// https://msdn.microsoft.com/ja-jp/library/windows/desktop/aa379804(v=vs.85).aspx
		[DllImport(FileName)]
		public static extern SCardResult SCardTransmit([In]IntPtr hCard, [In]IntPtr pioSendPci, [In]Byte[] pbSendBuffer, [In]UInt32 cbSendLength, [In, Out, Optional]ref SCardIORequest pioRecvPci, [Out]Byte[] pbRecvBuffer, [In, Out]ref UInt32 pcbRecvLength);

        [DllImport(FileName, EntryPoint = "SCardStatusW", CharSet = CharSet.Unicode)]
        public static extern SCardResult SCardStatus([In]IntPtr hCard, [Out]Char[] szReaderName, [In, Out, Optional]ref UInt32 pcchReaderLen, [Out, Optional]out UInt32 pdwState, [Out, Optional]out UInt32 pdwProtocol, [Out]Byte[] pbAtr, [In, Out, Optional]ref UInt32 pcbAtrLen);

        // - kernel DLL
        [DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr LoadLibrary(string lpFileName);

		[DllImport("kernel32.dll")]
		public static extern void FreeLibrary(IntPtr handle);

		[DllImport("kernel32.dll")]
		public static extern IntPtr GetProcAddress(IntPtr handle, string procName);

        // - Methods
        private static IntPtr GetPciT1() {
			IntPtr handle = LoadLibrary("winscard.dll");
			IntPtr result = GetProcAddress(handle, "g_rgSCardT1Pci");
			FreeLibrary(handle);
			return result;
		}

		public static int SCardTransmit(IntPtr hCard, byte[] sendData, byte[] recvData) {
			IntPtr         sendCode = GetPciT1();
			uint           sendSize = (uint)sendData.Length;
			uint           recvSize = (uint)recvData.Length;
			SCardIORequest recvCode = new SCardIORequest(0, recvSize + 2);
			SCardResult    result   = SCardTransmit(hCard, sendCode, sendData, sendSize, ref recvCode, recvData, ref recvSize);
			if (result == SCardResult.SCARD_S_SUCCESS) {
				return (int)recvSize;
			} else {
				return -1;
			}
		}

	}
}
