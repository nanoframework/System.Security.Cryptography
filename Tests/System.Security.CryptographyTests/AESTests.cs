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
        static byte[] cipherDataArray = new byte[] { 112, 15, 93, 166, 173, 66, 95, 251, 63, 172, 69, 69, 182, 109, 13, 93 };
        static byte[] clearDataArray = new byte[] { 78, 97, 110, 111, 102, 114, 97, 109, 101, 119, 111, 114, 107, 0, 0, 0 };
        static byte[] key = new byte[16] { 62, 110, 51, 201, 203, 48, 62, 150, 90, 219, 42, 55, 221, 109, 13, 93 };


        [TestMethod]
        public void TestAesECBEncryptionAndDecryption()
        {
            OutputHelper.WriteLine($"Test Case: ECB Encryption/Decryption");

            AES aes = new AES();
            aes.Mode = CipherMode.ECB;

            byte[] clearTextByteArrayWithPadding = clearDataArray;

            // Encrypt the bytes
            var enData = aes.Encrypt(key, clearTextByteArrayWithPadding);
            CollectionAssert.AreEqual(cipherDataArray,enData);


            // Decrypt the bytes
            var decryptedByteArray = aes.Decrypt(enData, key);
            CollectionAssert.AreEqual(clearDataArray, decryptedByteArray);

        }
    }
}
