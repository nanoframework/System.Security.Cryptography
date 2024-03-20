//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

using nanoFramework.TestFramework;
using System.Security.Cryptography;

namespace System.Security.CryptographyTests
{
    [TestClass]
    public partial class AesTests
    {
        /////////////////////////////////
        // CBC tests

        // the following test vectors were taken from NIST SP 800-38A
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        // the ciphered text was computed with a .NET console application using the AesManaged class

        static readonly byte[] iVCbc = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

        static readonly byte[] inputBlockCbc1 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
        static readonly byte[] ciphertextCbc1 = new byte[] { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d };

        static readonly byte[] inputBlockCbc2 = new byte[] { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
        static readonly byte[] ciphertextCbc2 = new byte[] { 0xbb, 0x44, 0x28, 0xe1, 0x37, 0x12, 0x72, 0x27, 0x50, 0xd4, 0xdb, 0xec, 0x82, 0x94, 0xbb, 0xa0 };

        static readonly byte[] inputBlockCbc3 = new byte[] { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
        static readonly byte[] ciphertextCbc3 = new byte[] { 0xd9, 0xf6, 0x49, 0x26, 0x63, 0x15, 0x8e, 0x94, 0x76, 0x64, 0x82, 0x06, 0x06, 0x52, 0x6b, 0x40 };

        static readonly byte[] inputBlockCbc4 = new byte[] { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
        static readonly byte[] ciphertextCbc4 = new byte[] { 0x27, 0xe1, 0xff, 0x0b, 0xdb, 0x5b, 0x68, 0xc6, 0x61, 0x3e, 0xc3, 0x0d, 0x7e, 0x59, 0xfc, 0xcc };

        [TestMethod]
        public void TestAesCBCEncryptionAndDecryption_00()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 00");

            Aes aes = new(CipherMode.CBC);
            aes.Key = key;
            aes.IV = iVCbc;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(inputBlockCbc1);
            CollectionAssert.AreEqual(
                ciphertextCbc1,
                encryptedData,
                "Encripted data value not expected.");

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                inputBlockCbc1,
                decryptedByteArray,
                "Decripted data value doesn't match the input value.");
        }

        [TestMethod]
        public void TestAesCBCEncryptionAndDecryption_01()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 01");

            Aes aes = new(CipherMode.CBC);
            aes.Key = key;
            aes.IV = iVCbc;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(inputBlockCbc2);
            CollectionAssert.AreEqual(
                ciphertextCbc2,
                encryptedData,
                "Encripted data value not expected.");

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                inputBlockCbc2,
                decryptedByteArray,
                "Decripted data value doesn't match the input value.");
        }

        [TestMethod]
        public void TestAesCBCEncryptionAndDecryption_02()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 02");

            Aes aes = new(CipherMode.CBC);
            aes.Key = key;
            aes.IV = iVCbc;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(inputBlockCbc3);
            CollectionAssert.AreEqual(
                ciphertextCbc3,
                encryptedData,
                "Encripted data value not expected.");

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                inputBlockCbc3,
                decryptedByteArray,
                "Decripted data value doesn't match the input value.");
        }


        [TestMethod]
        public void TestAesCBCEncryptionAndDecryption_03()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 03");

            Aes aes = new(CipherMode.CBC);
            aes.Key = key;
            aes.IV = iVCbc;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(inputBlockCbc4);
            CollectionAssert.AreEqual(
                ciphertextCbc4,
                encryptedData,
                "Encripted data value not expected.");

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                inputBlockCbc4,
                decryptedByteArray,
                "Decripted data value doesn't match the input value.");
        }

        [TestMethod]
        public void TestAesCBCEncryptionAndDecryption_Failing()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 02");

            /////////////////////////////////
            Aes aes = new(CipherMode.CBC);
            aes.Key = new byte[] { 1, 2, 3, 4, 5 };

            // should throw ArgumentException because the key is not 16 bytes
            Assert.ThrowsException(
                typeof(ArgumentException),
                () => aes.Encrypt(plainText1),
                "Should throw ArgumentException because the key is not 16 bytes.");

            /////////////////////////////////
            aes = new(CipherMode.CBC);

            // should throw InvalidOperationException because the key hasn't been set
            Assert.ThrowsException(
                typeof(InvalidOperationException),
                () => aes.Encrypt(plainText1),
                "Should throw InvalidOperationException because the key hasn't been set.");

            /////////////////////////////////
            aes = new(CipherMode.CBC);
            aes.Key = key;

            // should throw InvalidOperationException because the data is not a multiple of the block size (16 bytes)
            Assert.ThrowsException(
                typeof(ArgumentException),
                () => aes.Encrypt(new byte[] { 1, 2, 3, 4, 5 }),
                "Should throw ArgumentException because the data is not a multiple of the block size (16 bytes).");
        }

        [TestMethod]
        public void TestAesCBCEncryptionForMultiple32Bytes()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption for 32 bytes");

            Aes aes = new(CipherMode.CBC);
            aes.Key = key;
            aes.IV = iVCbc;

            byte[] Byte32ValueToEncrypt = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x6E, 0x69, 0x74, 0x65, 0x2E, 0x2E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };

            var encryptedData = aes.Encrypt(Byte32ValueToEncrypt);

            bool allZero = true;
            for (int i = 16; i < 32; i++)
            {
                if (encryptedData[i] != 0)
                {
                    allZero = false;
                }
            }

            Assert.IsFalse(allZero);

            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                Byte32ValueToEncrypt,
                decryptedByteArray);
        }
    }
}
