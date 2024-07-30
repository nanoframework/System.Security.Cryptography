//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

using nanoFramework.TestFramework;
using System.Security.Cryptography;

namespace System.Security.CryptographyTests
{
    public partial class AesTests
    {
        /////////////////////////////////
        // ECB tests

        static readonly byte[] plainText1 = new byte[] { 78, 97, 110, 111, 102, 114, 97, 109, 101, 119, 111, 114, 107, 0, 0, 0 };
        static readonly byte[] key1 = new byte[] { 198, 49, 248, 31, 20, 7, 226, 232, 208, 100, 15, 11, 2, 32, 213, 243 };
        static readonly byte[] cipherText1 = new byte[] { 116, 109, 190, 107, 121, 86, 239, 157, 179, 164, 65, 255, 12, 146, 120, 243 };

        // the following test vectors were taken from NIST SP 800-38A
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        static readonly byte[] key = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

        static readonly byte[] plainText2 = new byte[] { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
        static readonly byte[] cipherText2 = new byte[] { 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf };

        static readonly byte[] plainText3 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
        static readonly byte[] cipherText3 = new byte[] { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };

        static readonly byte[] plainText4 = new byte[] { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
        static readonly byte[] cipherText4 = new byte[] { 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4 };

        static readonly byte[] plainText5 = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x6E, 0x69, 0x74, 0x65, 0x2E, 0x2E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };
        static readonly byte[] cipherText5 = new byte[] { 87, 222, 42, 71, 76, 123, 33, 11, 1, 152, 33, 26, 155, 57, 62, 1, 44, 47, 3, 61, 173, 214, 191, 18, 222, 149, 39, 15, 101, 243, 215, 93 };

        [TestMethod]
        public void TestAesECBEncryptionAndDecryption_00()
        {
            OutputHelper.WriteLine($"Test Case: ECB Encryption/Decryption 00");

            Aes aes = new(CipherMode.ECB);
            aes.Key = key1;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(plainText1);
            CollectionAssert.AreEqual(
                cipherText1,
                encryptedData);

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                plainText1,
                decryptedByteArray);
        }

        [TestMethod]
        public void TestAesECBEncryptionAndDecryption_01()
        {
            OutputHelper.WriteLine($"Test Case: ECB Encryption/Decryption 01");

            Aes aes = new(CipherMode.ECB);
            aes.Key = key;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(plainText2);
            CollectionAssert.AreEqual(
                cipherText2,
                encryptedData);

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                plainText2,
                decryptedByteArray);
        }

        [TestMethod]
        public void TestAesECBEncryptionAndDecryption_02()
        {
            OutputHelper.WriteLine($"Test Case: ECB Encryption/Decryption 02");

            Aes aes = new(CipherMode.ECB);
            aes.Key = key;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(plainText3);
            CollectionAssert.AreEqual(
                cipherText3,
                encryptedData);

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                plainText3,
                decryptedByteArray);
        }


        [TestMethod]
        public void TestAesECBEncryptionAndDecryption_03()
        {
            OutputHelper.WriteLine($"Test Case: ECB Encryption/Decryption 03");

            Aes aes = new(CipherMode.ECB);
            aes.Key = key;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(plainText4);
            CollectionAssert.AreEqual(
                cipherText4,
                encryptedData);

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                plainText4,
                decryptedByteArray);
        }

        [TestMethod]
        public void TestAesECBEncryptionAndDecryption_Failing()
        {
            OutputHelper.WriteLine($"Test Case: ECB Encryption/Decryption 02");

            /////////////////////////////////
            Aes aes = new(CipherMode.ECB);
            aes.Key = new byte[] { 1, 2, 3, 4, 5 };

            // should throw ArgumentException because the key is not 16 bytes
            Assert.ThrowsException(
                typeof(ArgumentException),
                () => aes.Encrypt(plainText1),
                "Should throw ArgumentException because the key is not 16 bytes.");

            /////////////////////////////////
            aes = new(CipherMode.ECB);

            // should throw InvalidOperationException because the key hasn't been set
            Assert.ThrowsException(
                typeof(InvalidOperationException),
                () => aes.Encrypt(plainText1),
                "Should throw InvalidOperationException because the key hasn't been set.");

            /////////////////////////////////
            aes = new(CipherMode.ECB);
            aes.Key = key;

            // should throw ArgumentException because the data is not a multiple of the block size (16 bytes)
            Assert.ThrowsException(
                typeof(ArgumentException),
                () => aes.Encrypt(new byte[] { 1, 2, 3, 4, 5 }),
                "Should throw ArgumentException because the data is not a multiple of the block size (16 bytes).");
        }

        [TestMethod]
        public void TestAesECBEncryptionForMultiple32Bytes()
        {
            OutputHelper.WriteLine($"Test Case: ECB Encryption for 32 bytes");

            Aes aes = new(CipherMode.ECB);
            aes.Key = key;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(plainText5);
            CollectionAssert.AreEqual(
                cipherText5,
                encryptedData);

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                plainText5,
                decryptedByteArray);
        }
    }
}
