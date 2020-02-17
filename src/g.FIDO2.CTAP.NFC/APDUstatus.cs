using System;

namespace g.FIDO2.CTAP.NFC
{
    public class APDUstatus
    {
        public static bool IsSuccess(byte sw1,byte sw2)
        {
            if( sw1 == 0x90 && sw2 == 0x00) {
                return true;
            } else {
                return false;
            }
        }

        public static string GetMessage(byte sw1, byte sw2)
        {
            // http://eternalwindows.jp/security/scard/scard07.html

            if( sw1 == 0x90 && sw2 == 0x00) return ("正常終了");

            if( sw1 == 0x62) {
                if( sw2 == 0x81) return ("出力データに異常がある");
                if (sw2 == 0x83) return ("DFが閉塞(へいそく)している");
                return ("警告処理。不揮発性メモリの状態が変化していない");
            }

            if (sw1 == 0x63) {
                if (sw2 == 0x00) return ("照合不一致である");
                if (sw2 == 0x81) return ("ファイルが今回の書き込みによっていっぱいになった");
                if (sw2 >= 0xC0 && sw2 <= 0xCF) return ("照合不一致である。'n'によって、残りの再試行回数(1～15)を示す。");
                return ("警告処理。不揮発性メモリの状態が変化している");
            }

            if (sw1 == 0x64) {
                if (sw2 == 0x00) return ("ファイル制御情報に異常がある");
                return ("不揮発性メモリの状態が変化していない");
            }

            if (sw1 == 0x65) {
                if (sw2 == 0x00) return ("メモリへの書き込みが失敗した");
                return ("不揮発性メモリの状態が変化していない");
            }

            if (sw1 == 0x67) {
                if (sw2 == 0x00) return ("Lc/Leフィールドが間違っている");
            }

            if (sw1 == 0x68) {
                if (sw2 == 0x81) return ("指定された論理チャンネル番号によるアクセス機能を提供しない");
                if (sw2 == 0x82) return ("CLAバイトで指定されたセキュアメッセージング機能を提供しない");
                return ("CLAの機能が提供されない");
            }

            if (sw1 == 0x69) {
                if (sw2 == 0x81) return ("ファイル構造と矛盾したコマンドである");
                if (sw2 == 0x82) return ("セキュリティステータスが満足されない");
                if (sw2 == 0x83) return ("認証方法を受け付けない");
                if (sw2 == 0x84) return ("参照されたIEFが閉塞している");
                if (sw2 == 0x85) return ("コマンドの使用条件が満足されない");
                if (sw2 == 0x86) return ("ファイルが存在しない");
                if (sw2 == 0x87) return ("セキュアメッセージングに必要なデータオブジェクトが存在しない");
                if (sw2 == 0x88) return ("セキュアメッセージング関連エラー");
                return ("コマンドは許されない");
            }

            if (sw1 == 0x6a) {
                if (sw2 == 0x80) return ("データフィールドのタグが正しくない");
                if (sw2 == 0x81) return ("機能が提供されていない");
                if (sw2 == 0x82) return ("ファイルが存在しない");
                if (sw2 == 0x83) return ("アクセス対象のレコードがない");
                if (sw2 == 0x84) return ("ファイル内に十分なメモリ容量がない");
                if (sw2 == 0x85) return ("Lcの値がTLV構造に矛盾している");
                if (sw2 == 0x86) return ("P1 - P2の値が正しくない");
                if (sw2 == 0x87) return ("Lcの値がP1 - P2に矛盾している");
                if (sw2 == 0x88) return ("参照された鍵が正しく設定されていない");
                return ("間違ったパラメータP1,P2");
            }

            if (sw1 == 0x6b) {
                if (sw2 == 0x00) return ("EF範囲外にオフセット指定した");
            }

            if (sw1 == 0x6d) {
                if (sw2 == 0x00) return ("INSが提供されていない");
            }

            if (sw1 == 0x6e) {
                if (sw2 == 0x00) return ("CLAが提供されていない");
            }

            if (sw1 == 0x6f) {
                if (sw2 == 0x00) return ("自己診断異常");
            }

            return ("不明なエラー");
        }
    }
}
