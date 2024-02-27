//
// Copyright (c) .NET Foundation and Contributors
// See LICENSE file in the project root for full license information.
//

using System.Runtime.CompilerServices;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Provides an Advanced Encryption Standard (AES) algorithm to encrypt and decrypt data.
    /// </summary>
    public class Aes
    {
        private CipherMode _mode;
        private byte[] _key;
        private byte[] _iv;

        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm.
        /// </summary>
        /// <value>The mode for operation of the symmetric algorithm.</value>
        public CipherMode Mode { get => _mode; set => _mode = value; }

        /// <summary>
        /// Gets or sets the secret key for the symmetric algorithm.
        /// </summary>
        /// <value>The secret key for the symmetric algorithm.</value>
        public byte[] Key { get => _key; set => _key = value; }

        /// <summary>
        /// Gets or sets the initialization vector for the symmetric algorithm.
        /// </summary>
        /// <value>The initialization vector.</value>
        public byte[] IV { get => _iv; set => _iv = value; }

        /// <summary>
        /// Initializes a new instance of the <see cref="Aes"/> class.
        /// </summary>
        public Aes(CipherMode mode)
        {
            Mode = mode;

            if (Mode == CipherMode.CBC)
            {
                _iv = new byte[16];

                // Fill the IV with random data
                Random random = new Random();
                random.NextBytes(_iv);
            }
        }

        /// <summary>
        /// Encrypts data using the cipher specified in <see cref="Mode"/>.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>The encrypted ciphertext data.</returns>
        /// <exception cref="InvalidOperationException">If the <see cref="Key"/> hasn't been set.</exception>
        /// <exception cref="ArgumentException">If the data in not a multiple of the block size (16 bytes for AES).</exception>
        public byte[] Encrypt(byte[] data)
        {
            switch (Mode)
            {
                case CipherMode.ECB:
                    return EncryptAesEcb(data);

                case CipherMode.CBC:
                    return EncryptAesCbc(data);

                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Decrypts data using cipher specified in <see cref="Mode"/>.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <returns>The decrypted plaintext data.</returns>
        /// <exception cref="InvalidOperationException">If the <see cref="Key"/> hasn't been set.</exception>
        /// <exception cref="ArgumentException">If the data in not a multiple of the block size (16 bytes for AES).</exception>
        public byte[] Decrypt(byte[] data)
        {
            switch (Mode)
            {
                case CipherMode.ECB:
                    return DecryptAesEcb(data);

                case CipherMode.CBC:
                    return DecryptAesCbc(data);

                default:
                    throw new NotSupportedException();
            }
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        private extern byte[] EncryptAesEcb(byte[] data);

        [MethodImpl(MethodImplOptions.InternalCall)]
        private extern byte[] DecryptAesEcb(byte[] data);

        [MethodImpl(MethodImplOptions.InternalCall)]
        private extern byte[] EncryptAesCbc(byte[] data);

        [MethodImpl(MethodImplOptions.InternalCall)]
        private extern byte[] DecryptAesCbc(byte[] data);
    }
}
