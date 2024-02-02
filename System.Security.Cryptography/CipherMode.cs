//
// Copyright (c) .NET Foundation and Contributors
// See LICENSE file in the project root for full license information.
//

namespace System.Security.Cryptography
{
    /// <summary>
    /// Specifies the block cipher mode to use for encryption.
    /// </summary>
    public enum CipherMode
    {
        /// <summary>
        /// No cipher mode set. 
        /// </summary>
        None = 0,

        /// <summary>
        /// The Electronic Codebook (ECB) mode encrypts each block individually. Any blocks
        /// of plain text that are identical and in the same message, or that are in a different
        /// message encrypted with the same key, will be transformed into identical cipher
        /// text blocks. **Important:** This mode is not recommended because it opens the door
        /// for multiple security exploits. If the plain text to be encrypted contains substantial
        /// repetition, it is feasible for the cipher text to be broken one block at a time.
        /// It is also possible to use block analysis to determine the encryption key. Also,
        /// an active adversary can substitute and exchange individual blocks without detection,
        /// which allows blocks to be saved and inserted into the stream at other points
        /// without detection.
        /// </summary>
        ECB = 2
    }
}
