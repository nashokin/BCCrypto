using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;

namespace BCCrypto
{
    class Program
    {
        // Base64 encoded salt string, also known as encoding parameters
        private static readonly string _saltBase64 = "cEAkJHcwcmQ=";

        private static readonly string _password = "p@$$w0rd";

        public enum Action { Encrypt, Decrypt }

        static void Main(string[] args)
        {
            // Encrypt RSA-OAEP with public key
            CryptoAction(
                @"../../../input/test.txt",
                @"../../../output/test (encrypted).rsa",
                //@"../../../input/RFC 8017 - PKCS #1_ RSA Cryptography Specifications Version 2.2.pdf",
                //@"../../../output/RFC 8017 - PKCS #1_ RSA Cryptography Specifications Version 2.2 (encrypted).rsa",
                @"../../../keys/public.pem",
                Standards.RsaOaep,
                Action.Encrypt
                );

            // Decrypt RSA-OAEP with private key
            CryptoAction(
                @"../../../output/test (encrypted).rsa",
                @"../../../output/test (decrypted).txt",
                //@"../../../output/RFC 8017 - PKCS #1_ RSA Cryptography Specifications Version 2.2 (encrypted).rsa",
                //@"../../../output/RFC 8017 - PKCS #1_ RSA Cryptography Specifications Version 2.2 (decrypted).pdf",
                @"../../../keys/private.pem",
                Standards.RsaOaep,
                Action.Decrypt
                );

            //// Encrypt OpenPGP with public key
            //CryptoAction(
            //    @"../../../input/RFC 4880 - OpenPGP Message Format.html",
            //    @"../../../output/RFC 4880 - OpenPGP Message Format (encrypted).gpg",
            //    @"../../../keys/public.gpg",
            //    Standards.OpenPgp,
            //    Action.Encrypt
            //    );

            //// Decrypt OpenPGP with private key
            //CryptoAction(
            //    @"../../../output/RFC 4880 - OpenPGP Message Format (encrypted).gpg",
            //    @"../../../output/RFC 4880 - OpenPGP Message Format (decrypted).html",
            //    @"../../../keys/private.gpg",
            //    Standards.OpenPgp,
            //    Action.Decrypt
            //    );

            Console.WriteLine("Enjoy cryptography!");
        }

        public static void CryptoAction(string inputFile, string outputFile, string inputKey, string standard, Action action)
        {
            using (Stream input = File.OpenRead(inputFile), output = File.Create(outputFile), key = File.OpenRead(inputKey))
            {
                try
                {
                    switch (standard)
                    {
                        case "RSAES-OAEP":
                            if (action.Equals(Action.Encrypt))
                            {
                                EncryptRsa(input, output, key, Convert.FromBase64String(_saltBase64));
                            }
                            else if (action.Equals(Action.Decrypt))
                            {
                                DecryptRsa(input, output, key, Convert.FromBase64String(_saltBase64), _password.ToCharArray());
                            }
                            break;
                        case "OpenPGP":
                            if (action.Equals(Action.Encrypt))
                            {
                                EncryptPgp(input, output, key);
                            }
                            else if (action.Equals(Action.Decrypt))
                            {
                                DecryptPgp(input, output, key, _password.ToCharArray());
                            }
                            break;
                        default:
                            Console.WriteLine("Encryption standard is not supported.");
                            break;
                    };
                }
                catch (Exception ex)
                {
                    Console.WriteLine(string.Format("{0}{1}{2}", ex.Message, Environment.NewLine, ex.InnerException));
                }
            }
        }

        private static void EncryptRsa(Stream input, Stream output, Stream key, byte[] salt)
        {
            using (StreamReader streamReader = new StreamReader(key))
            {
                AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)new PemReader(streamReader).ReadObject();

                using (MemoryStream inputMemory = new MemoryStream(), outputMemory = new MemoryStream())
                {
                    input.CopyTo(inputMemory);
                    byte[] inputBytes = inputMemory.ToArray();

                    IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest(), salt);
                    cipher.Init(true, publicKey);

                    // Can't figure out why this is not working as expected, please advise if you know
                    //int length = 0;
                    //byte[] buffer = new byte[cipher.GetInputBlockSize()];
                    //inputMemory.Seek(0, SeekOrigin.Begin);
                    //while ((length = inputMemory.Read(buffer, 0, buffer.Length)) > 0)
                    //{
                    //    byte[] ciphered = cipher.ProcessBlock(buffer, 0, length);
                    //    outputMemory.Write(ciphered, 0, ciphered.Length);
                    //}

                    int length = inputBytes.Length;
                    int blockSize = cipher.GetInputBlockSize();
                    for (int offset = 0; offset < length; offset += blockSize)
                    {
                        int chunkSize = Math.Min(blockSize, length - offset);
                        byte[] ciphered = cipher.ProcessBlock(inputBytes, offset, chunkSize);
                        outputMemory.Write(ciphered, 0, ciphered.Length);
                    }

                    outputMemory.WriteTo(output);

                    Console.WriteLine("RSA-OAEP encryption successfull.");
                }
            }
        }

        private static void DecryptRsa(Stream input, Stream output, Stream key, byte[] salt, char[] password)
        {
            using (StreamReader streamReader = new StreamReader(key))
            {
                AsymmetricCipherKeyPair cipherKeyPair = (AsymmetricCipherKeyPair)new PemReader(streamReader, new PasswordFinder(password)).ReadObject();

                using (MemoryStream inputMemory = new MemoryStream(), outputMemory = new MemoryStream())
                {
                    input.CopyTo(inputMemory);
                    byte[] inputBytes = inputMemory.ToArray();

                    IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), new Sha256Digest(), salt);
                    cipher.Init(false, cipherKeyPair.Private);

                    // Can't figure out why this is not working as expected, please advise if you know
                    //int length = 0;
                    //byte[] buffer = new byte[cipher.GetOutputBlockSize()];
                    //inputMemory.Seek(0, SeekOrigin.Begin);
                    //while ((length = inputMemory.Read(buffer, 0, buffer.Length)) > 0)
                    //{
                    //    byte[] deciphered = cipher.ProcessBlock(buffer, 0, length);
                    //    outputMemory.Write(deciphered, 0, deciphered.Length);
                    //}

                    int length = inputBytes.Length;
                    int blockSize = cipher.GetInputBlockSize();
                    for (int offset = 0; offset < length; offset += blockSize)
                    {
                        int chunkSize = Math.Min(blockSize, length - offset);
                        byte[] deciphered = cipher.ProcessBlock(inputBytes, offset, chunkSize);
                        outputMemory.Write(deciphered, 0, deciphered.Length);
                    }

                    outputMemory.WriteTo(output);

                    Console.WriteLine("RSA-OAEP decryption successfull.");
                }
            }
        }

        private static bool EncryptPgp(Stream input, Stream output, Stream key)
        {
            return true;
        }

        private static bool DecryptPgp(Stream input, Stream output, Stream key, char[] password)
        {
            return true;
        }
    }
}
