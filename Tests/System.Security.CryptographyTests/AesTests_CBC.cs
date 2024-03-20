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

        static byte[] iVCbc = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

        static byte[] inputBlockCbc1 = new byte[] { 0x6b, 0xc0, 0xbc, 0xe1, 0x2a, 0x45, 0x99, 0x91, 0xe1, 0x34, 0x74, 0x1a, 0x7f, 0x9e, 0x19, 0x25 };
        static byte[] ciphertextCbc1 = new byte[] { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d };

        static byte[] inputBlockCbc2 = new byte[] { 0xd8, 0x64, 0x21, 0xfb, 0x9f, 0x1a, 0x1e, 0xda, 0x50, 0x5e, 0xe1, 0x37, 0x57, 0x46, 0x97, 0x2c };
        static byte[] ciphertextCbc2 = new byte[] { 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 };

        static byte[] inputBlockCbc3 = new byte[] { 0x60, 0x4e, 0xd7, 0xdd, 0xf3, 0x2e, 0xfd, 0xff, 0x70, 0x20, 0xd0, 0x23, 0x8b, 0x7c, 0x2a, 0x5d };
        static byte[] ciphertextCbc3 = new byte[] { 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16 };

        static byte[] inputBlockCbc4 = new byte[] { 0x85, 0x21, 0xf2, 0xfd, 0x3c, 0x8e, 0xef, 0x2c, 0xdc, 0x3d, 0xa7, 0xe5, 0xc4, 0x4e, 0xa2, 0x06 };
        static byte[] ciphertextCbc4 = new byte[] { 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };

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

            //// Decrypt the bytes
            //var decryptedByteArray = aes.Decrypt(encryptedData);
            //CollectionAssert.AreEqual(
            //    inputBlockCbc1,
            //    decryptedByteArray,
            //    "Decripted data value doesn't match the input value.");
        }

        //[TestMethod]
        //public void TestAesCBCEncryptionAndDecryption_01()
        //{
        //    OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 01");

        //    Aes aes = new(CipherMode.CBC);
        //    aes.Key = keyCbc;
        //    aes.IV = iVCbc;

        //    // Encrypt the bytes
        //    var encryptedData = aes.Encrypt(inputBlockCbc2);
        //    CollectionAssert.AreEqual(
        //        ciphertextCbc2,
        //        encryptedData);

        //    // Decrypt the bytes
        //    var decryptedByteArray = aes.Decrypt(encryptedData);
        //    CollectionAssert.AreEqual(
        //        inputBlockCbc2,
        //        decryptedByteArray);
        //}

        //[TestMethod]
        //public void TestAesCBCEncryptionAndDecryption_02()
        //{
        //    OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 02");

        //    Aes aes = new(CipherMode.CBC);
        //    aes.Key = keyCbc;
        //    aes.IV = iVCbc;

        //    // Encrypt the bytes
        //    var encryptedData = aes.Encrypt(inputBlockCbc3);
        //    CollectionAssert.AreEqual(
        //        ciphertextCbc3,
        //        encryptedData);

        //    // Decrypt the bytes
        //    var decryptedByteArray = aes.Decrypt(encryptedData);
        //    CollectionAssert.AreEqual(
        //        inputBlockCbc3,
        //        decryptedByteArray);
        //}


        //[TestMethod]
        //public void TestAesCBCEncryptionAndDecryption_03()
        //{
        //    OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 03");

        //    Aes aes = new(CipherMode.CBC);
        //    aes.Key = keyCbc;
        //    aes.IV = iVCbc;

        //    // Encrypt the bytes
        //    var encryptedData = aes.Encrypt(inputBlockCbc4);
        //    CollectionAssert.AreEqual(
        //        ciphertextCbc4,
        //        encryptedData);

        //    // Decrypt the bytes
        //    var decryptedByteArray = aes.Decrypt(encryptedData);
        //    CollectionAssert.AreEqual(
        //        inputBlockCbc4,
        //        decryptedByteArray);
        //}

        //[TestMethod]
        //public void TestAesCBCEncryptionAndDecryption_Failing()
        //{
        //    OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 02");

        //    /////////////////////////////////
        //    Aes aes = new(CipherMode.CBC);
        //    aes.Key = new byte[] { 1, 2, 3, 4, 5 };

        //    // should throw ArgumentException because the key is not 16 bytes
        //    Assert.ThrowsException(
        //        typeof(ArgumentException),
        //        () => aes.Encrypt(plainText1));

        //    /////////////////////////////////
        //    aes = new(CipherMode.CBC);

        //    // should throw InvalidOperationException because the key hasn't been set
        //    Assert.ThrowsException(
        //        typeof(InvalidOperationException),
        //        () => aes.Encrypt(plainText1));

        //    /////////////////////////////////
        //    aes = new(CipherMode.CBC);
        //    aes.Key = key2;

        //    // should throw InvalidOperationException because the data is not a multiple of the block size (16 bytes)
        //    Assert.ThrowsException(
        //        typeof(InvalidOperationException),
        //        () => aes.Encrypt(new byte[] { 1, 2, 3, 4, 5 }));
        //}

        //[TestMethod]
        //public void TestAesCBCEncryptionForMultiple32Bytes()
        //{
        //    OutputHelper.WriteLine($"Test Case: CBC Encryption for 32 bytes");

        //    Aes aes = new(CipherMode.CBC);
        //    aes.Key = keyCbc;
        //    aes.IV = iVCbc;

        //    byte[] Byte32ValueToEncrypt = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x43, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x6E, 0x69, 0x74, 0x65, 0x2E, 0x2E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35 };

        //    var encryptedData = aes.Encrypt(Byte32ValueToEncrypt);

        //    bool allZero = true;
        //    for (int i = 16; i < 32; i++)
        //    {
        //        if (encryptedData[i] != 0)
        //        {
        //            allZero = false;
        //        }
        //    }

        //    Assert.IsFalse(allZero);

        //    var decryptedByteArray = aes.Decrypt(encryptedData);
        //    CollectionAssert.AreEqual(
        //        Byte32ValueToEncrypt,
        //        decryptedByteArray);
        //}
    }
}
