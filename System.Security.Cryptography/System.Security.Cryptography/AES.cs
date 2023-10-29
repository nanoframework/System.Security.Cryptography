using System;

namespace System.Security.Cryptography
{
    public class AES
    {
        public enum EncryptionModes { ECB }
        public EncryptionModes Mode { get; set; } = EncryptionModes.ECB;

        public byte[] Encrypt(byte[] key, byte[] data)
        {
            byte[] buf = null;

            if (Mode == EncryptionModes.ECB)
            {
                buf = EncryptAesEcb(key, data);
            }

            return buf;
        }

        public byte[] Decrypt(byte[] key, byte[] data)
        {
            byte[] buf = null;

            if (Mode == EncryptionModes.ECB)
            {
                buf = DecryptAesEcb(key, data);
            }

            return buf;
        }
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
