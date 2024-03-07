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
    public class AESTests
    {
        static byte[] plainText1 = new byte[] { 78, 97, 110, 111, 102, 114, 97, 109, 101, 119, 111, 114, 107, 0, 0, 0 };
        static byte[] key1 = new byte[] { 198, 49, 248, 31, 20, 7, 226, 232, 208, 100, 15, 11, 2, 32, 213, 243 };
        static byte[] cipherText1 = new byte[] { 129, 36, 97, 206, 48, 62, 96, 137, 162, 125, 201, 110, 1, 119, 84, 195 };


        // the following test vectors were taken from NIST SP 800-38A
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

        static byte[] key2 = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

        static byte[] plainText2 = new byte[] { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
        static byte[] cipherText2 = new byte[] { 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf };

        static byte[] plainText3 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
        static byte[] cipherText3 = new byte[] { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };

        static byte[] plainText4 = new byte[] { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
        static byte[] cipherText4 = new byte[] { 0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4 };

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
            aes.Key = key2;

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
            aes.Key = key2;

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
            aes.Key = key2;

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
                () => aes.Encrypt(plainText1));

            /////////////////////////////////
            aes = new(CipherMode.ECB);

            // should throw InvalidOperationException because the key hasn't been set
            Assert.ThrowsException(
                typeof(InvalidOperationException),
                () => aes.Encrypt(plainText1));

            /////////////////////////////////
            aes = new(CipherMode.ECB);
            aes.Key = key2;

            // should throw InvalidOperationException because the data is not a multiple of the block size (16 bytes)
            Assert.ThrowsException(
                typeof(InvalidOperationException),
                () => aes.Encrypt(new byte[] { 1, 2, 3, 4, 5 }));
        }

        [TestMethod]
        public void TestAesECBEncryptionForMultiple32Bytes()
        {
            OutputHelper.WriteLine($"Test Case: ECB Encryption for 32 bytes");

            Aes aes = new(CipherMode.ECB);
            aes.Key = key1;

            byte[] Byte32ValueToEncrypt = Encoding.UTF8.GetBytes("Hello this is Cryptonite..012345");

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


        //CBC tests


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
            aes.Key = key2;

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
            aes.Key = key2;

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
            aes.Key = key2;

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
                () => aes.Encrypt(plainText1));

            /////////////////////////////////
            aes = new(CipherMode.ECB);

            // should throw InvalidOperationException because the key hasn't been set
            Assert.ThrowsException(
                typeof(InvalidOperationException),
                () => aes.Encrypt(plainText1));

            /////////////////////////////////
            aes = new(CipherMode.ECB);
            aes.Key = key2;

            // should throw InvalidOperationException because the data is not a multiple of the block size (16 bytes)
            Assert.ThrowsException(
                typeof(InvalidOperationException),
                () => aes.Encrypt(new byte[] { 1, 2, 3, 4, 5 }));
        }

        [TestMethod]
        public void TestAesECBEncryptionForMultiple32Bytes()
        {
            OutputHelper.WriteLine($"Test Case: ECB Encryption for 32 bytes");

            Aes aes = new(CipherMode.ECB);
            aes.Key = key1;

            byte[] Byte32ValueToEncrypt = Encoding.UTF8.GetBytes("Hello this is Cryptonite..012345");

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






        //CBC tests
        static byte[] KeyCbc = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
        static byte[] IVCbc = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        
        //static byte[] PlaintextCbc1 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
        static byte[] InputBlockCbc1 = new byte[] { 0x6b, 0xc0, 0xbc, 0xe1, 0x2a, 0x45, 0x99, 0x91, 0xe1, 0x34, 0x74, 0x1a, 0x7f, 0x9e, 0x19, 0x25 };
        //static byte[] OutputBlockCbc1 = new byte[] { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d };
        static byte[] CiphertextCbc1 = new byte[] { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d };
        
        //static byte[] PlaintextCbc2 = new byte[] { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
        static byte[] InputBlockCbc2 = new byte[] { 0xd8, 0x64, 0x21, 0xfb, 0x9f, 0x1a, 0x1e, 0xda, 0x50, 0x5e, 0xe1, 0x37, 0x57, 0x46, 0x97, 0x2c };
        //static byte[] OutputBlockCbc2 = new byte[] { 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 };
        static byte[] CiphertextCbc2 = new byte[] { 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 };
        
        //static byte[] PlaintextCbc3 = new byte[] { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
        static byte[] InputBlockCbc3 = new byte[] { 0x60, 0x4e, 0xd7, 0xdd, 0xf3, 0x2e, 0xfd, 0xff, 0x70, 0x20, 0xd0, 0x23, 0x8b, 0x7c, 0x2a, 0x5d };
        //static byte[] OutputBlockCbc3 = new byte[] { 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16 };
        static byte[] CiphertextCbc3 = new byte[] { 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16 };
        
        //static byte[] PlaintextCbc4 = new byte[] { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
        static byte[] InputBlockCbc4 = new byte[] { 0x85, 0x21, 0xf2, 0xfd, 0x3c, 0x8e, 0xef, 0x2c, 0xdc, 0x3d, 0xa7, 0xe5, 0xc4, 0x4e, 0xa2, 0x06 };
        //static byte[] OutputBlockCbc4 = new byte[] { 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
        static byte[] CiphertextCbc4 = new byte[] { 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };

        public void TestAesCBCEncryptionAndDecryption_00()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 00");

            Aes aes = new(CipherMode.CBC);
            aes.Key = KeyCbc;
            aes.IV = IVCbc;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(InputBlockCbc1);
            CollectionAssert.AreEqual(
                CiphertextCbc1,
                encryptedData);

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                InputBlockCbc1,
                decryptedByteArray);
        }

        [TestMethod]
        public void TestAesCBCEncryptionAndDecryption_01()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 01");

            Aes aes = new(CipherMode.CBC);
            aes.Key = KeyCbc;
            aes.IV = IVCbc;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(InputBlockCbc2);
            CollectionAssert.AreEqual(
                CiphertextCbc2,
                encryptedData);

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                InputBlockCbc2,
                decryptedByteArray);
        }

        [TestMethod]
        public void TestAesCBCEncryptionAndDecryption_02()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 02");

            Aes aes = new(CipherMode.CBC);
            aes.Key = KeyCbc;
            aes.IV = IVCbc;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(InputBlockCbc3);
            CollectionAssert.AreEqual(
                CiphertextCbc3,
                encryptedData);

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                InputBlockCbc3,
                decryptedByteArray);
        }


        [TestMethod]
        public void TestAesCBCEncryptionAndDecryption_03()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption/Decryption 03");

            Aes aes = new(CipherMode.CBC);
            aes.Key = KeyCbc;
            aes.IV = IVCbc;

            // Encrypt the bytes
            var encryptedData = aes.Encrypt(InputBlockCbc4);
            CollectionAssert.AreEqual(
                CiphertextCbc4,
                encryptedData);

            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(encryptedData);
            CollectionAssert.AreEqual(
                InputBlockCbc4,
                decryptedByteArray);
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
                () => aes.Encrypt(plainText1));

            /////////////////////////////////
            aes = new(CipherMode.CBC);

            // should throw InvalidOperationException because the key hasn't been set
            Assert.ThrowsException(
                typeof(InvalidOperationException),
                () => aes.Encrypt(plainText1));

            /////////////////////////////////
            aes = new(CipherMode.CBC);
            aes.Key = key2;

            // should throw InvalidOperationException because the data is not a multiple of the block size (16 bytes)
            Assert.ThrowsException(
                typeof(InvalidOperationException),
                () => aes.Encrypt(new byte[] { 1, 2, 3, 4, 5 }));
        }

        [TestMethod]
        public void TestAesCBCEncryptionForMultiple32Bytes()
        {
            OutputHelper.WriteLine($"Test Case: CBC Encryption for 32 bytes");

            Aes aes = new(CipherMode.CBC);
            aes.Key = KeyCbc;
            aes.IV = IVCbc;

            byte[] Byte32ValueToEncrypt = Encoding.UTF8.GetBytes("Hello this is Cryptonite..012345");

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
