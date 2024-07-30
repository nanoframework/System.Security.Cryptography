[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=nanoframework_System.Security.Cryptography&metric=alert_status)](https://sonarcloud.io/dashboard?id=nanoframework_System.Security.Cryptography) [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=nanoframework_System.Security.Cryptography&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=nanoframework_System.Security.Cryptography) [![NuGet](https://img.shields.io/nuget/dt/nanoFramework.System.Security.Cryptography.svg?label=NuGet&style=flat&logo=nuget)](https://www.nuget.org/packages/nanoFramework.System.Security.Cryptography/) [![#yourfirstpr](https://img.shields.io/badge/first--timers--only-friendly-blue.svg)](https://github.com/nanoframework/Home/blob/main/CONTRIBUTING.md) [![Discord](https://img.shields.io/discord/478725473862549535.svg?logo=discord&logoColor=white&label=Discord&color=7289DA)](https://discord.gg/gCyBu8T)

![nanoFramework logo](https://raw.githubusercontent.com/nanoframework/Home/main/resources/logo/nanoFramework-repo-logo.png)

-----

# Welcome to the .NET **nanoFramework** System.Security.Cryptography Library repository

This repository contains the nanoFramework System.Security.Cryptography class library.

## Build status

| Component | Build Status | NuGet Package |
|:-|---|---|
| System.Security.Cryptography | [![Build Status](https://dev.azure.com/nanoframework/System.Security.Cryptography/_apis/build/status%2FSystem.Security.Cryptography?branchName=main)](https://dev.azure.com/nanoframework/System.Security.Cryptography/_build/latest?definitionId=68&branchName=main) | [![NuGet](https://img.shields.io/nuget/v/nanoFramework.System.Security.Cryptography.svg?label=NuGet&style=flat&logo=nuget)](https://www.nuget.org/packages/nanoFramework.System.Security.Cryptography/) |

## System.Security.Cryptography usage

This library brings to .NET nanoFramework C# applications the equivalent implementations provided by Mbed TLS. The target there the code is going to be deployed has to have a firmware image built with this namespace enabled.

### HMAC SHA256

This class computes a Hash-based Message Authentication Code (HMAC) by using the SHA256 hash function.

A typical usage for this, in IoT context, is to compute an _hashed_ signature to connect to Azure IoT Hub. Like

Providing one has the _S_hared _A_ccess _K_ey and wants to encode a certain _Uri_ the code snippet that does this is as simple has this:

```csharp
var hmacsha256 = new HMACSHA256(Convert.FromBase64String(sharedAccessKey));

byte[] hash = hmacsha256.ComputeHash(Encoding.UTF8.GetBytes(encodedUri + "\n" + expiry));

string sig = Convert.ToBase64String(hash);
```

### AES

Advanced Encryption Standard (AES)

[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) is a variant of the Rijndael block cipher with different key and block sizes. For AES, NIST selected three members of the Rijndael family, each with a block size of 128 bits, but three different key lengths: 128, 192 and 256 bits.

The current version has support for the ECB and CBC modes.
The following examples demonstrates how to encrypt and decrypt sample data by using the AES class.

Note that the input data has to be multiple of 16 bits, otherwise an exception will be thrown.
Data shorter than that should be padded with zeros.

#### ECB-AES128

```csharp
//Sample Usage
string clearText = "Nanoframework";
byte[] clearTextByteArray = Encoding.UTF8.GetBytes(clearText);
// please note the array size: 16 bytes
byte[] clearTextByteArrayWithPadding = new byte[16];
Array.Copy(clearTextByteArray, 0, clearTextByteArrayWithPadding, 0, clearTextByteArray.Length);

// Create a new instance of the Aes
AES aes = new AES(CipherMode.ECB);
aes.Key = new byte[16] { 198, 49, 248, 31, 20, 7, 226, 232, 208, 100, 15, 11, 2, 32, 213, 243 };

// Encrypt the bytes to a string.
var encryptedData = aes.Encrypt(clearTextByteArrayWithPadding);
string encryptedText = Encoding.UTF8.GetString(encryptedData);
Debug.WriteLine(encryptedText);

// Decrypt the bytes to a string.
var decryptedByteArray = aes.Decrypt(encryptedData);
string decryptedText = Encoding.UTF8.GetString(decryptedByteArray);
Debug.WriteLine(decryptedText);
```

#### CBC-AES128

```csharp
//Sample Usage
byte[] inputBlockCbc1 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };

// Create a new instance of the Aes class for CBC
Aes aes = new(CipherMode.CBC);
aes.Key = new byte[] { 198, 49, 248, 31, 20, 7, 226, 232, 208, 100, 15, 11, 2, 32, 213, 243 };;
aes.IV = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

// Encrypt the bytes
var encryptedData = aes.Encrypt(inputBlockCbc1);
string encryptedText = Encoding.UTF8.GetString(encryptedData);
Debug.WriteLine(encryptedText);

// Decrypt the bytes to a string.
var decryptedByteArray = aes.Decrypt(encryptedData);
string decryptedText = Encoding.UTF8.GetString(decryptedByteArray);
Debug.WriteLine(decryptedText);
```

## Feedback and documentation

For documentation, providing feedback, issues and finding out how to contribute please refer to the [Home repo](https://github.com/nanoframework/Home).

Join our Discord community [here](https://discord.gg/gCyBu8T).

## Credits

The list of contributors to this project can be found at [CONTRIBUTORS](https://github.com/nanoframework/Home/blob/main/CONTRIBUTORS.md).

## License

The **nanoFramework** Class Libraries are licensed under the [MIT license](LICENSE.md).

## Code of Conduct

This project has adopted the code of conduct defined by the Contributor Covenant to clarify expected behaviour in our community.
For more information see the [.NET Foundation Code of Conduct](https://dotnetfoundation.org/code-of-conduct).

### .NET Foundation

This project is supported by the [.NET Foundation](https://dotnetfoundation.org).
