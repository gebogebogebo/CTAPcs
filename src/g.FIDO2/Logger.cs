using System;
using System.Collections.Generic;
using System.Linq;

namespace g.FIDO2
{
    public static class Logger
    {
        public static void SetEnable(bool enable)
        {
            //LoggingServices.Enabled = enable;
        }

        public static void Err(string msg)
        {
            Console.WriteLine(msg);
        }

        public static void Err(Exception ex, string msg = "")
        {
            Logger.Err($"Exception...{ex.Message}),message={msg}");
        }

        public static void Log(string msg)
        {
            Console.WriteLine(msg);
        }

    }


}

