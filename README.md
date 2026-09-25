# AES CNG PowerShell

PowerShell script for file encryption and decryption using **AES-256-CBC**, **HMAC-SHA256**, and **PBKDF2-HMAC-SHA256**, implemented through the native Windows **CNG / BCrypt API** (`bcrypt.dll`).

> **Security note:** This code was produced with the help of AI (Sonnet 5 and GPT-5.6 Luna free tiers). The code provided has not undergone an independent security audit. Please use it at your own risk.

## Features

- AES-256-CBC encryption and decryption
- Encrypt-then-MAC design
- HMAC-SHA256 authentication
- PBKDF2-HMAC-SHA256 with **600,000 iterations**
- One 64-byte PBKDF2 output split into two independent 32-byte keys:
    - 32 bytes for AES-256
    - 32 bytes for HMAC-SHA256
- Fresh random 16-byte salt and IV for every encryption
- Streaming processing with a configurable buffer
- Does not load the complete file into memory
- HMAC verification is completed before decrypted data is committed to the final output path
- Temporary output files are used to avoid leaving a partial final file after an error
- AES-256 and PBKDF2 use Windows CNG / `bcrypt.dll`

## Compatibility

|System|Status|
|---|---|
|Windows 7|Tested|
|Windows 10|Supported|
|Windows 11|Tested|
|Windows Vista|**Not supported**|
|Windows XP|**Not supported**|
|Windows 98 / 98 SE|**Not supported**|
|Windows 95|**Not supported**|

The practical target is **Windows 7 and later**.

The script is designed for **PowerShell 2.0+** and conservative .NET Framework environments. It therefore avoids newer PowerShell syntax and newer .NET APIs where possible.

The embedded C# also avoids newer language features so that it can be compiled by the older C# compiler available through `Add-Type` on legacy PowerShell installations.

## Usage

### Help

```powershell
.\aes-cng.ps1 -h
```

### Encrypt a file

```powershell
.\aes-cng.ps1 -Encrypt -In .\input.iso -Out .\input.iso.enc
```

The password is requested twice during encryption.

### Decrypt a file

```powershell
.\aes-cng.ps1 -Decrypt -In .\input.iso.enc -Out .\input.iso
```

The password is requested once during decryption.

### Change the I/O buffer size

The default buffer is **8 MiB**.

```powershell
.\aes-cng.ps1 -Encrypt -In .\input.iso -Out .\input.iso.enc -BufferSize 16MB
```

The buffer must be between **64 KiB and 64 MiB** and must be a multiple of **16 bytes**.

## Cryptographic design

The password is processed with:

```text
PBKDF2-HMAC-SHA256
600,000 iterations
64-byte derived key
```

The derived material is split into two separate keys:

```text
Password
   |
   v
PBKDF2-HMAC-SHA256
600,000 iterations
   |
   | 64 bytes
   +-----------------------+
   |                       |
   v                       v
32-byte AES key       32-byte HMAC key
   |                       |
   v                       v
AES-256-CBC            HMAC-SHA256
```

A fresh random **16-byte salt** is generated for every encryption. The salt prevents the same password from producing the same derived keys across different files.

A fresh random **16-byte IV** is also generated for every encryption. The IV is stored in the file header and is not secret.

### HMAC-SHA256

A separate 32-byte HMAC key is derived from the same PBKDF2 operation.

The HMAC covers:

```text
Ciphertext
     +
   Header
(Magic + Salt + IV + Ciphertext)
     |
     v
 HMAC-SHA256
```

This authenticates both the encrypted data and the security-relevant header fields.

## File format

Every encrypted file begins with the fixed magic value: **AESPS002**

The complete header is **72 bytes**:

```text
┌────────────┬────────────┬────────────┬────────────────┬──────────────────┐
│ Magic 8 B  │ Salt 16 B  │ IV 16 B    │ HMAC 32 B      │ Ciphertext       │
│ AESPS002   │ random     │ random     │ authentication │ AES-256-CBC      │
└────────────┴────────────┴────────────┴────────────────┴──────────────────┘
```

The salt and IV are stored in plaintext by design. They are not secret values.

## Encryption flow

```text
1. Validate source/destination paths
2. Generate random salt and IV
3. Derive AES and HMAC keys with PBKDF2
4. Create a temporary output file
5. Write Magic + Salt + IV + placeholder HMAC
6. Read plaintext in chunks
7. Encrypt each chunk with AES-256-CBC
8. Feed ciphertext into HMAC-SHA256
9. Write the final HMAC into the header
10. Commit the temporary file to the requested output path
```

If the operation fails, the temporary file is removed when possible.

## Decryption flow

```text
1. Validate source/destination paths
2. Validate the 72-byte header
3. Derive AES and HMAC keys with PBKDF2
4. Recalculate HMAC over Magic + Salt + IV + Ciphertext
5. Compare tags in constant time
6. Stop immediately if authentication fails
7. Decrypt ciphertext to a temporary output file
8. Commit the temporary file to the requested output path
```

The final output path is therefore only created after authentication succeeds and the decryption operation completes.

## Memory and file handling

The implementation tries to minimize the lifetime of sensitive material:

- AES and HMAC keys are cleared after use.
- Derived intermediate key material is cleared after the two keys are extracted.
- Salt and IV buffers are cleared after use.
- CNG key objects and algorithm handles are explicitly destroyed or closed.
- Temporary output files are deleted after failed operations when possible.
- Files are processed as streams rather than loaded entirely into memory.
- The password is kept in `SecureString` until it needs to be passed to the C# engine.
- The plaintext password is created as late as practical and its reference is released immediately after the engine call.

A .NET `string` is immutable and cannot be reliably zeroed. This limits how completely the plaintext password can be removed from managed memory.

## Performance

A development benchmark on Windows 11 using a **7.89 GB Windows 11 ISO** produced approximately:

```text
PBKDF2-HMAC-SHA256 : 0.28 s
AES-256-CBC        : 7.29 s
HMAC-SHA256        : 4.20 s
Total              : 19.14 s
```

These figures are indicative and depend on the CPU, storage device, Windows version, .NET environment, file size, and buffer size.
