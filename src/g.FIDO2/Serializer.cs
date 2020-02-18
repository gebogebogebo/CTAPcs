using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;

namespace g.FIDO2
{

    public class Serializer
    {
        public static byte[] Serialize(Attestation att)
        {
            return (serialize((object)att));
        }

        public static byte[] Serialize(Assertion ass)
        {
            return (serialize((object)ass));
        }

        private static byte[] serialize(object obj)
        {
            try {
                using (var ms = new MemoryStream()) {
                    var formatter = new BinaryFormatter();
                    formatter.Serialize(ms, obj);
                    return (ms.ToArray());
                }
            } catch (Exception ex) {
                return null;
            }
        }

        public static Attestation DeserializeAttestation(byte[] byteData)
        {
            try {
                using (var mem = new MemoryStream(byteData.Length)) {
                    mem.Write(byteData, 0, byteData.Length);
                    mem.Seek(0, SeekOrigin.Begin);
                    var formatter = new BinaryFormatter();
                    return (Attestation)formatter.Deserialize(mem);
                }
            }catch(Exception ex) {
                return null;
            }
        }

        public static Assertion DeserializeAssertion(byte[] byteData)
        {
            return (Assertion)deserialize(byteData);
        }

        public static object deserialize(byte[] byteData)
        {
            try {
                using (var mem = new MemoryStream(byteData.Length)) {
                    mem.Write(byteData, 0, byteData.Length);
                    mem.Seek(0, SeekOrigin.Begin);
                    var formatter = new BinaryFormatter();
                    return formatter.Deserialize(mem);
                }
            } catch (Exception ex) {
                return null;
            }
        }

    }
}

