using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;
using System.Runtime.InteropServices;

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
            string currentDirectory = Environment.CurrentDirectory;
            string prefix;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                prefix = string.Format("{0}/", currentDirectory);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                prefix = Path.GetFullPath(string.Format("{0}/{1}", currentDirectory, "../../../"));
            }
            else
            {
                return;
            }

            // Encrypt RSA-OAEP with public key
            CryptoAction(
                string.Format("{0}{1}", prefix, "input/test.txt"),
                string.Format("{0}{1}", prefix, "output/test (encrypted).rsa"), // included small text file for faster test run
                //string.Format("{0}{1}", prefix, "input/RFC 8017 - PKCS #1_ RSA Cryptography Specifications Version 2.2.html"),
                //string.Format("{0}{1}", prefix, "output/RFC 8017 - PKCS #1_ RSA Cryptography Specifications Version 2.2 (encrypted).rsa"),
                string.Format("{0}{1}", prefix, "keys/public.pem"),
                Standards.RsaOaep,
                Action.Encrypt
                );

            // Decrypt RSA-OAEP with private key
            CryptoAction(
                string.Format("{0}{1}", prefix, "output/test (encrypted).rsa"),
                string.Format("{0}{1}", prefix, "output/test (decrypted).txt"), // included small text file for faster test run
                //string.Format("{0}{1}", prefix, "output/RFC 8017 - PKCS #1_ RSA Cryptography Specifications Version 2.2 (encrypted).rsa"),
                //string.Format("{0}{1}", prefix, "output/RFC 8017 - PKCS #1_ RSA Cryptography Specifications Version 2.2 (decrypted).html"),
                string.Format("{0}{1}", prefix, "keys/private.pem"),
                Standards.RsaOaep,
                Action.Decrypt
                );

            // Encrypt OpenPGP with public key
            CryptoAction(
                string.Format("{0}{1}", prefix, "input/RFC 4880 - OpenPGP Message Format.pdf"),
                string.Format("{0}{1}", prefix, "output/RFC 4880 - OpenPGP Message Format (encrypted).gpg"),
                string.Format("{0}{1}", prefix, "keys/public.gpg"),
                Standards.OpenPgp,
                Action.Encrypt
                );

            // Decrypt OpenPGP with private key
            CryptoAction(
                string.Format("{0}{1}", prefix, "output/RFC 4880 - OpenPGP Message Format (encrypted).gpg"),
                string.Format("{0}{1}", prefix, "output/RFC 4880 - OpenPGP Message Format (decrypted).pdf"),
                string.Format("{0}{1}", prefix, "keys/private.gpg"),
                Standards.OpenPgp,
                Action.Decrypt
                );

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
                                EncryptPgp(input, output, key, true, true);
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

        #region RSA
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
        #endregion

        #region OpenPGP
        private static void EncryptPgp(Stream input, Stream output, Stream key, bool armor, bool integrityCheck)
        {
            try
            {
                // Find public key for encryption
                PgpPublicKey publicKey = null;
                PgpPublicKeyRingBundle pgpPublicKeyRingBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(key));
                foreach (PgpPublicKeyRing pkr in pgpPublicKeyRingBundle.GetKeyRings())
                {
                    foreach (PgpPublicKey pKey in pkr.GetPublicKeys())
                    {
                        if (pKey.IsEncryptionKey)
                        {
                            publicKey = pKey;
                            break;
                        }
                    }
                }

                if (publicKey == null)
                {
                    throw new ArgumentException("Public key for encryption not found.");
                }

                MemoryStream inputMemory = new MemoryStream();
                input.CopyTo(inputMemory);
                byte[] bytes = inputMemory.ToArray(); // clear data bytes
                inputMemory.Close();

                MemoryStream compressedLiteral = new MemoryStream();
                PgpCompressedDataGenerator pgpCompressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.BZip2);
                Stream compressed = pgpCompressedDataGenerator.Open(compressedLiteral);

                PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
                Stream literal = pgpLiteralDataGenerator.Open(compressed, PgpLiteralData.Binary, "STREAM", bytes.Length, DateTime.UtcNow);
                literal.Write(bytes, 0, bytes.Length);

                pgpLiteralDataGenerator.Close();
                pgpCompressedDataGenerator.Close();

                PgpEncryptedDataGenerator pgpEncryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, integrityCheck, new SecureRandom());
                pgpEncryptedDataGenerator.AddMethod(publicKey);

                bytes = compressedLiteral.ToArray(); // compressed literal data bytes

                MemoryStream encryptedMemory = new MemoryStream();
                Stream os = encryptedMemory;

                // optional armor ASCII encoding
                if (armor)
                {
                    os = new ArmoredOutputStream(os);
                }

                Stream encrypted = pgpEncryptedDataGenerator.Open(os, bytes.Length);
                encrypted.Write(bytes, 0, bytes.Length);
                encrypted.Close();

                if (armor)
                {
                    os.Close();
                }

                encryptedMemory.Seek(0, SeekOrigin.Begin);
                Streams.PipeAll(encryptedMemory, output);
                encryptedMemory.Close();

                Console.WriteLine("OpenPGP encryption successfull.");
            }
            catch (PgpException ex)
            {
                Console.Error.WriteLine(ex);

                Exception pgpInnerException = ex.InnerException;
                if (pgpInnerException != null)
                {
                    Console.Error.WriteLine(pgpInnerException.Message);
                    Console.Error.WriteLine(pgpInnerException.StackTrace);
                }
            }
        }

        private static void DecryptPgp(Stream input, Stream output, Stream key, char[] password)
        {
            try
            {
                PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(input));
                PgpObject pgpObject = pgpObjectFactory.NextPgpObject();

                // The first object might be a PGP marker packet
                PgpEncryptedDataList pgpEncryptedDataList;
                if (pgpObject is PgpEncryptedDataList)
                {
                    pgpEncryptedDataList = (PgpEncryptedDataList)pgpObject;
                }
                else
                {
                    pgpEncryptedDataList = (PgpEncryptedDataList)pgpObjectFactory.NextPgpObject();
                }

                // Find private key for decryption
                PgpPrivateKey privateKey = null;
                PgpSecretKeyRingBundle pgpSecretKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(key));
                PgpPublicKeyEncryptedData pgpPublicKeyEncryptedData = null;
                foreach (PgpPublicKeyEncryptedData pked in pgpEncryptedDataList.GetEncryptedDataObjects())
                {
                    PgpSecretKey pgpDescretKey = pgpSecretKeyRing.GetSecretKey(pked.KeyId);
                    privateKey = pgpDescretKey.ExtractPrivateKey(password);

                    if (privateKey != null)
                    {
                        pgpPublicKeyEncryptedData = pked;
                        break;
                    }
                }

                if (privateKey == null)
                {
                    throw new ArgumentException("Private key for decryption not found.");
                }

                Stream decrypted = pgpPublicKeyEncryptedData.GetDataStream(privateKey);
                pgpObjectFactory = new PgpObjectFactory(decrypted);
                pgpObject = pgpObjectFactory.NextPgpObject();

                if (pgpObject is PgpCompressedData)
                {
                    PgpCompressedData pgpCompressedData = (PgpCompressedData)pgpObject;
                    pgpObjectFactory = new PgpObjectFactory(pgpCompressedData.GetDataStream());
                    pgpObject = pgpObjectFactory.NextPgpObject();
                }

                if (pgpObject is PgpLiteralData)
                {
                    PgpLiteralData pgpLiteralData = (PgpLiteralData)pgpObject;
                    Stream literal = pgpLiteralData.GetInputStream();
                    Streams.PipeAll(literal, output);
                }
                else if (pgpObject is PgpOnePassSignatureList)
                {
                    throw new PgpException("Encrypted message contains a signed message, not a literal data.");
                }
                else
                {
                    throw new PgpException("Message is not a simple encrypted file, type is unknown.");
                }

                if (pgpPublicKeyEncryptedData.IsIntegrityProtected())
                {
                    if (!pgpPublicKeyEncryptedData.Verify())
                    {
                        Console.Error.WriteLine("Message failed integrity check.");
                    }
                    else
                    {
                        Console.Error.WriteLine("Message integrity check passed.");
                    }
                }
                else
                {
                    Console.Error.WriteLine("No message integrity check.");
                }

                Console.WriteLine("OpenPGP decryption successfull.");
            }
            catch (PgpException ex)
            {
                Console.Error.WriteLine(ex);

                Exception pgpInnerException = ex.InnerException;
                if (pgpInnerException != null)
                {
                    Console.Error.WriteLine(pgpInnerException.Message);
                    Console.Error.WriteLine(pgpInnerException.StackTrace);
                }
            }
        }
        #endregion
    }
}
