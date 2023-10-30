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
