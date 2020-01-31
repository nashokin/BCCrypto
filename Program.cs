using System;
using System.IO;

namespace BCCrypto
{
    class Program
    {
        static void Main(string[] args)
        {




            Console.WriteLine("Enjoy cryptography!");
        }

        public static void Encrypt(string inputFile, string publicKey, string standard)
        {
            using (Stream input = File.OpenRead(inputFile), key = File.OpenRead(publicKey))
            {
                switch (standard)
                {
                    case "RSAES-OAEP":
                        EncryptRsa(input, key, null);
                        break;
                    case "OpenPGP":
                        EncryptPgp(input, key);
                        break;
                    default:
                        Console.WriteLine("Encryption standard is not supported.");
                        break;
                };
            }
        }

        public static void Decrypt(string inputFile, string privateKey, string standard)
        {
            using (Stream input = File.OpenRead(inputFile), key = File.OpenRead(privateKey))
            {
                switch (standard)
                {
                    case "RSAES-OAEP":
                        DencryptRsa(input, key, null, null);
                        break;
                    case "OpenPGP":
                        DencryptPgp(input, key, null);
                        break;
                    default:
                        Console.WriteLine("Encryption standard is not supported.");
                        break;
                };
            }
        }

        private static bool EncryptRsa(Stream input, Stream key, Stream hash)
        {
            return true;
        }

        private static bool DencryptRsa(Stream input, Stream key, Stream hash, char[] password)
        {
            return true;
        }

        private static bool EncryptPgp(Stream input, Stream key)
        {
            return true;
        }

        private static bool DencryptPgp(Stream input, Stream key, char[] password)
        {
            return true;
        }
    }
}
