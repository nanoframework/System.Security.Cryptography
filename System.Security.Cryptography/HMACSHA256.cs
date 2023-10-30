//
// Copyright (c) .NET Foundation and Contributors
// Portions Copyright (c) Microsoft Corporation.  All rights reserved.
// See LICENSE file in the project root for full license information.
//

using System.Runtime.CompilerServices;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Computes a Hash-based Message Authentication Code (HMAC) by using the SHA256 hash function.
    /// </summary>
    public class HMACSHA256 : IDisposable
    {
        private bool _disposed;
        private byte[] _keyValue = null;
        private byte[] _hashValue;

        /// <summary>
        /// Gets the value of the computed hash code.
        /// </summary>
        /// <value>The current value of the computed hash code.</value>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        public byte[] Hash
        {
            get
            {
                if (_disposed)
                {
                    throw new ObjectDisposedException();
                }

                return (byte[])_hashValue.Clone();
            }
        }

        /// <summary>
        /// Gets or sets the key to use in the HMAC calculation.
        /// </summary>
        /// <value>The key to use in the HMAC calculation.</value>
        /// <remarks>
        /// <para>
        /// This property is the key for the keyed hash algorithm.
        /// </para>
        /// <para>
        /// A Hash-based Message Authentication Code (HMAC) can be used to determine whether a message sent over an insecure channel has been tampered with, provided that the sender and receiver share a secret key. The sender computes the hash value for the original data and sends both the original data and the HMAC as a single message. The receiver recomputes the hash value on the received message and checks that the computed hash value matches the transmitted hash value.
        /// </para>
        /// </remarks>
        public byte[] Key
        {
            get
            {
                return (byte[])_keyValue.Clone();
            }

            set
            {
                _keyValue = (byte[])value.Clone() ?? throw new ArgumentNullException();
            }
        }

        /// <summary>
        /// Initializes a new instance of the HMACSHA256 class with a randomly generated key.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <see cref="HMACSHA256"/> is a type of keyed hash algorithm that is constructed from the SHA-256 hash function and used as a Hash-based Message Authentication Code (HMAC). The HMAC process mixes a secret key with the message data, hashes the result with the hash function, mixes that hash value with the secret key again, and then applies the hash function a second time. The output hash is 256 bits in length.
        /// </para>
        /// <para>
        /// This constructor uses a 64-byte, randomly generated key.
        /// </para>
        /// </remarks>
        public HMACSHA256()
        {
            // Generate a random key with 64 bytes
            Random generator = new();
            _keyValue = new byte[64];
            generator.NextBytes(_keyValue);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HMACSHA256"/> class with the specified key data.
        /// </summary>
        /// <param name="key">The secret key for HMAC computation. The key can be any length. However, the recommended size is 64 bytes. If the key is more than 64 bytes long, it is hashed (using SHA-256) to derive a 32-byte key.</param>
        /// <exception cref="ArgumentNullException">The <paramref name="key"/> parameter is <see langword="null"/>.</exception>
        /// <remarks>
        /// <see cref="HMACSHA256"/> is a type of keyed hash algorithm that is constructed from the SHA-256 hash function and used as a Hash-based Message Authentication Code (HMAC). The HMAC process mixes a secret key with the message data, hashes the result with the hash function, mixes that hash value with the secret key again, and then applies the hash function a second time. The output hash is 256 bits in length.
        /// </remarks>
        public HMACSHA256(byte[] key)
        {
            _keyValue = key ?? throw new ArgumentNullException();
        }

        /// <summary>
        /// Computes the hash value for the specified byte array.
        /// </summary>
        /// <param name="buffer">The input to compute the hash code for.</param>
        /// <returns>The computed hash code.</returns>
        /// <exception cref="ObjectDisposedException">The object has already been disposed.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <see langword="null"/>.</exception>
        public byte[] ComputeHash(byte[] buffer)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException();
            }

            // Developer note: "buffer" parameter is checked for null by HashCore()
            
            _hashValue = HashCore(_keyValue, buffer);

            return (byte[])_hashValue.Clone();
        }

        /// <summary>
        /// Computes the HMAC of data using the SHA256 algorithm.
        /// </summary>
        /// <param name="key">The HMAC key.</param>
        /// <param name="source">The data to HMAC.</param>\
        /// <returns>The HMAC of the data.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="key" /> or <paramref name="source" /> is <see langword="null" />.
        /// </exception>
        public static byte[] HashData(
            byte[] key,
            byte[] source)
        {
            // Developer note: "key" and "source" parameters are checked for null by HashCore()

            return HashCore(key, source);
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <inheritdoc/>
        protected void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_keyValue != null)
                {
                    Array.Clear(_keyValue, 0, _keyValue.Length);
                }

                _keyValue = null;

                // Although we don't have any resources to dispose at this level,
                // we need to continue to throw ObjectDisposedExceptions from CalculateHash
                // for compatibility with the .NET Framework.
                _disposed = true;
            }

            return;
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        extern private static byte[] HashCore(byte[] key, byte[] source);
    }
}
