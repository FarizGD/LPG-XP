# LPG-XP

LPG-XP uses FXPENC, its versioned encrypted game package format. This first implementation adds a standalone .NET 8 library and command-line packer without changing the existing editor or runtime.

## Requirements

- .NET 8 SDK
- Windows or Linux for the packer CLI.
- .NET for Android workload for Android builds. The archive library targets both `net8.0` and `net8.0-android`.

## Build

```sh
dotnet build src/LPG-XP.CLI/LPG-XP.CLI.csproj -c Release
```

## Create a game key

```sh
dotnet run --project src/LPG-XP.CLI -- keygen game.key --csharp GameArchiveKey.cs
```

The key is a random 32-byte AES-256 key. Keep `game.key` and `GameArchiveKey.cs` private and out of public source control. Generate a different key for each game release.

## Package a game build

Package a deployment-ready copy of the game, not your working project directory:

```sh
dotnet run --project src/LPG-XP.CLI -- pack ./GameBuild ./Game.fxpenc ./game.key
```

Inspect and extract for debugging:

```sh
dotnet run --project src/LPG-XP.CLI -- list ./Game.fxpenc ./game.key
dotnet run --project src/LPG-XP.CLI -- extract ./Game.fxpenc ./Extracted ./game.key
```

## Runtime API

Reference `src/LPG-XP.Core/LPG-XP.Core.csproj` from a .NET 8 or .NET for Android runtime:

```csharp
byte[] key = LPGXP.Generated.GameArchiveKey.GetKey();
try
{
    byte[] bytes = LPGXP.Archive.FxpencArchive.ReadFile("Game.fxpenc", "Graphics/Titles1.png", key);
    // Decode the returned bytes directly using the runtime's asset API.
}
finally
{
    System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
}
```

The current `ReadFile` API authenticates and walks the archive from its beginning to the requested file, so repeated random asset loads can be slow. A future optimized version should add an authenticated index and seekable chunk layout. The current implementation is a format prototype, not yet integrated into RPG Maker XP's RGSS runtime.

## Security notes

- AES-256-GCM authenticates the manifest and each data chunk. A wrong key or modified archive should fail authentication.
- Players are not prompted for a password. The game runtime uses the key compiled into its build.
- An embedded key can be recovered by a determined reverse engineer. FXPENC is not unbreakable DRM.
- Do not package editor-only files, private keys, or generated key source into the archive.

## Compatibility

FXPENC is not compatible with RPG Maker XP's `.rgssad`. Existing `.rxproj` projects remain ordinary project folders. This addition does not make the legacy WinForms editor or RGSS runtime run on Android by itself.
