//
// Copyright (c) .NET Foundation and Contributors
// See LICENSE file in the project root for full license information.
//

using System;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Represents the class for aes encryption/decryption
    /// </summary>
    public class AES
    {
        public enum EncryptionModes { ECB }
        public EncryptionModes Mode { get; set; } = EncryptionModes.ECB;

        /// <summary>
        /// Encrypt the array of bytes.
        /// </summary>
        /// <param name="key">The secret key to use for the symmetric algorithm.</param>
        /// <param name="data">array of bytes for encryption</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] key, byte[] data)
        {
            byte[] buf = null;

            if (Mode == EncryptionModes.ECB)
            {
                buf = EncryptAesEcb(key, data);
            }

            return buf;
        }

        /// <summary>
        /// Decrypt the array of bytes.
        /// </summary>
        /// <param name="key">The secret key to use for the symmetric algorithm.</param>
        /// <param name="data">encrypted array of bytes for decryption</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] key, byte[] data)
        {
            byte[] buf = null;

            if (Mode == EncryptionModes.ECB)
            {
                buf = DecryptAesEcb(key, data);
            }

            return buf;
        }

        /// <summary>
        /// Encrypt the array of bytes In ECB Mode
        /// </summary>
        /// <param name="key">The secret key to use for the symmetric algorithm.</param>
        /// <param name="data">Array of bytes for encryption</param>
        /// <returns></returns>
        private byte[] EncryptAesEcb(byte[] key, byte[] data)
        {
            int blockSize = 16; // AES block size is 128 bits (16 bytes)
            int blockCount = data.Length / blockSize;
            int remainder = data.Length % blockSize;

            byte[] encryptedData = new byte[data.Length];

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(data, i * blockSize, block, 0, blockSize);
                EncryptBlock(key, block);
                Array.Copy(block, 0, encryptedData, i * blockSize, blockSize);
            }

            // If there is a remainder, pad the last block and encrypt
            if (remainder > 0)
            {
                byte[] lastBlock = new byte[blockSize];
                Array.Copy(data, blockCount * blockSize, lastBlock, 0, remainder);
                EncryptBlock(key, lastBlock);
                Array.Copy(lastBlock, 0, encryptedData, blockCount * blockSize, remainder);
            }

            return encryptedData;
        }

        /// <summary>
        /// XOR the block of data with key
        /// </summary>
        /// <param name="key">The secret key for XOR opration with block </param>
        /// <param name="block">The Block of data for XOR opration with secret key</param>
        /// <exception cref="ArgumentException"></exception>
        private void EncryptBlock(byte[] key, byte[] block)
        {
            // Ensure that the key and block have the same length
            if (key.Length != block.Length)
            {
                throw new ArgumentException("Key and block must have the same length.");
            }

            for (int i = 0; i < block.Length; i++)
            {
                block[i] = (byte)(block[i] ^ key[i]);
            }
        }

        /// <summary>
        /// Decrypt the array of bytes In ECB Mode
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] DecryptAesEcb(byte[] key, byte[] data)
        {
            int blockSize = 16; // AES block size is 128 bits (16 bytes)
            int blockCount = data.Length / blockSize;
            int remainder = data.Length % blockSize;

            byte[] decryptedData = new byte[data.Length];

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(data, i * blockSize, block, 0, blockSize);
                DecryptBlock(key, block);
                Array.Copy(block, 0, decryptedData, i * blockSize, blockSize);
            }

            // If there is a remainder, pad the last block and decrypt
            if (remainder > 0)
            {
                byte[] lastBlock = new byte[blockSize];
                Array.Copy(data, blockCount * blockSize, lastBlock, 0, remainder);
                DecryptBlock(key, lastBlock);
                Array.Copy(lastBlock, 0, decryptedData, blockCount * blockSize, remainder);
            }

            return decryptedData;
        }

        /// <summary>
        /// XOR the block of data with key
        /// </summary>
        /// <param name="key">The secret key for XOR opration with block </param>
        /// <param name="block">The Block of data for XOR opration with secret key</param>
        /// <exception cref="ArgumentException"></exception>
        private void DecryptBlock(byte[] key, byte[] block)
        {
            // Ensure that the key and block have the same length
            if (key.Length != block.Length)
            {
                throw new ArgumentException("Key and block must have the same length.");
            }

            for (int i = 0; i < block.Length; i++)
            {
                block[i] = (byte)(block[i] ^ key[i]);
            }
        }
    }
}
