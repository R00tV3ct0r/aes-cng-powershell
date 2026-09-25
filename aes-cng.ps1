<#
    AES-256-CBC + HMAC-SHA256
    PBKDF2-HMAC-SHA256: 600000 iterations

    Format: [ Magic 8B ][ Salt 16B ][ IV 16B ][ HMAC 32B ][ Ciphertext ... ]
    Magic: AESPS002

    Targets: Windows 7/10/11, PowerShell 2.0+, old .NET Framework.
    AES-256-CBC and PBKDF2 use Windows CNG (bcrypt.dll); HMAC uses HMACSHA256.

    The AESPS002 format and cryptographic parameters are unchanged from aes.ps1.
#>

[CmdletBinding(DefaultParameterSetName = 'Help')]
param(
    [Parameter(ParameterSetName = 'Encrypt', Mandatory = $true)]
    [switch]$Encrypt,

    [Parameter(ParameterSetName = 'Decrypt', Mandatory = $true)]
    [switch]$Decrypt,

    [Parameter(ParameterSetName = 'Encrypt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Decrypt', Mandatory = $true)]
    [Alias('InFile')]
    [string]$In,

    [Parameter(ParameterSetName = 'Encrypt', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Decrypt', Mandatory = $true)]
    [Alias('OutFile')]
    [string]$Out,

    [Parameter(ParameterSetName = 'Encrypt')]
    [Parameter(ParameterSetName = 'Decrypt')]
    [ValidateRange(65536, 67108864)]
    [int]$BufferSize = 8MB,

    [Parameter(ParameterSetName = 'Help')]
    [Alias('h')]
    [switch]$Help
)

if (-not ('AesCngFileEngine' -as [type])) {

    $source = @'
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;

public static class AesCngFileEngine
{

    private const int KdfIterations = 600000;

    private const int MagicSize = 8;
    private const int SaltSize = 16;
    private const int IvSize = 16;
    private const int TagSize = 32;
    private const int HeaderSize = MagicSize + SaltSize + IvSize + TagSize;
    private const int AesBlockSize = 16;

    private const int STATUS_SUCCESS = 0;
    private const uint BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008;
    private const uint BCRYPT_BLOCK_PADDING = 0x00000001;

    private static readonly byte[] Magic =
        Encoding.ASCII.GetBytes("AESPS002");

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int BCryptOpenAlgorithmProvider(
        out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int BCryptCloseAlgorithmProvider(
        IntPtr hAlgorithm, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int BCryptSetProperty(
        IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int BCryptGetProperty(
        IntPtr hObject, string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int BCryptGenerateSymmetricKey(
        IntPtr hAlgorithm, out IntPtr phKey, byte[] pbKeyObject, uint cbKeyObject,
        byte[] pbSecret, uint cbSecret, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int BCryptEncrypt(
        IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo,
        byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int BCryptDecrypt(
        IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo,
        byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int BCryptDeriveKeyPBKDF2(
        IntPtr hPrf, byte[] pbPassword, uint cbPassword, byte[] pbSalt, uint cbSalt,
        ulong cIterations, byte[] pbDerivedKey, uint cbDerivedKey, uint dwFlags);

    // General helpers
    private static void CheckStatus(int status, string operation)
    {
        if (status != STATUS_SUCCESS)
        {
            throw new CryptographicException(
                operation + " failed. NTSTATUS=0x" + status.ToString("X8"));
        }
    }

    private static int GetInt32Property(IntPtr handle, string propertyName)
    {
        byte[] buffer = new byte[4];
        int resultLength;

        int status = BCryptGetProperty(handle, propertyName, buffer, buffer.Length, out resultLength, 0);
        CheckStatus(status, "BCryptGetProperty(" + propertyName + ")");

        if (resultLength < 4)
        {
            throw new CryptographicException("BCryptGetProperty returned an invalid property size.");
        }

        return BitConverter.ToInt32(buffer, 0);
    }

    private static IntPtr OpenAesAlgorithm()
    {
        IntPtr algorithm;

        int status = BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0);
        CheckStatus(status, "BCryptOpenAlgorithmProvider(AES)");

        try
        {
            byte[] mode = Encoding.Unicode.GetBytes("ChainingModeCBC\0");
            status = BCryptSetProperty(algorithm, "ChainingMode", mode, mode.Length, 0);
            CheckStatus(status, "BCryptSetProperty(ChainingModeCBC)");
            return algorithm;
        }
        catch
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            throw;
        }
    }

    private static IntPtr CreateAesKey(IntPtr algorithm, byte[] key, out byte[] keyObject)
    {
        int objectLength = GetInt32Property(algorithm, "ObjectLength");

        if (objectLength <= 0)
        {
            throw new CryptographicException("Invalid AES key object size.");
        }

        keyObject = new byte[objectLength];

        IntPtr keyHandle;
        int status = BCryptGenerateSymmetricKey(
            algorithm, out keyHandle, keyObject, (uint)keyObject.Length, key, (uint)key.Length, 0);

        CheckStatus(status, "BCryptGenerateSymmetricKey");
        return keyHandle;
    }

    // File helpers
    private static FileStream OpenInput(string path)
    {
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
    }

    private static FileStream OpenOutput(string path)
    {
        return new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.SequentialScan);
    }

    private static string TempPath(string outputPath)
    {
        return outputPath + ".tmp-" + Guid.NewGuid().ToString("N");
    }

    private static void CommitTemp(string tempPath, string outputPath)
    {
        if (File.Exists(outputPath))
        {
            File.Replace(tempPath, outputPath, null);
        }
        else
        {
            File.Move(tempPath, outputPath);
        }
    }

    // Reads up to the buffer size; returns 0 only at EOF.
    private static int ReadUpTo(Stream stream, byte[] buffer)
    {
        int total = 0;

        while (total < buffer.Length)
        {
            int read = stream.Read(buffer, total, buffer.Length - total);
            if (read <= 0) break;
            total += read;
        }

        return total;
    }

    private static int ReadExactlyCount(Stream stream, byte[] buffer, int count)
    {
        int total = 0;

        while (total < count)
        {
            int read = stream.Read(buffer, total, count - total);
            if (read <= 0)
            {
                throw new InvalidDataException("Unexpected end of file.");
            }
            total += read;
        }

        return total;
    }

    // Authentication helpers
    private static byte[] BuildMacPrefix(byte[] salt, byte[] iv)
    {
        byte[] prefix = new byte[MagicSize + SaltSize + IvSize];

        Buffer.BlockCopy(Magic, 0, prefix, 0, MagicSize);
        Buffer.BlockCopy(salt, 0, prefix, MagicSize, SaltSize);
        Buffer.BlockCopy(iv, 0, prefix, MagicSize + SaltSize, IvSize);

        return prefix;
    }

    private static bool FixedTimeEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length) return false;

        int diff = 0;
        int i;

        for (i = 0; i < a.Length; i++)
        {
            diff |= a[i] ^ b[i];
        }

        return diff == 0;
    }

    // Key derivation
    private static byte[] Pbkdf2Sha256(string password, byte[] salt, int iterations, int derivedKeyLength)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] derived = new byte[derivedKeyLength];

        IntPtr algorithm = IntPtr.Zero;

        try
        {
            int status = BCryptOpenAlgorithmProvider(out algorithm, "SHA256", null, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            CheckStatus(status, "BCryptOpenAlgorithmProvider(SHA256/HMAC)");

            status = BCryptDeriveKeyPBKDF2(
                algorithm, passwordBytes, (uint)passwordBytes.Length, salt, (uint)salt.Length,
                (ulong)iterations, derived, (uint)derived.Length, 0);

            CheckStatus(status, "BCryptDeriveKeyPBKDF2");
            return derived;
        }
        finally
        {
            if (algorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(algorithm, 0);
            if (passwordBytes != null) Array.Clear(passwordBytes, 0, passwordBytes.Length);
        }
    }

    private static void DeriveKeys(string password, byte[] salt, out byte[] encKey, out byte[] macKey)
    {
        byte[] material = Pbkdf2Sha256(password, salt, KdfIterations, 64);

        encKey = new byte[32];
        macKey = new byte[32];

        Buffer.BlockCopy(material, 0, encKey, 0, 32);
        Buffer.BlockCopy(material, 32, macKey, 0, 32);

        Array.Clear(material, 0, material.Length);
    }

    // AES-CBC
    private static int EncryptChunk(IntPtr keyHandle, byte[] input, int inputLength, byte[] iv, byte[] output)
    {
        int outputLength;

        int status = BCryptEncrypt(
            keyHandle, input, inputLength, IntPtr.Zero, iv, iv.Length, output, output.Length, out outputLength, 0);

        CheckStatus(status, "BCryptEncrypt");
        return outputLength;
    }

    private static int DecryptChunk(
        IntPtr keyHandle, byte[] input, int inputLength, byte[] iv, byte[] output, bool finalChunk)
    {
        int outputLength;
        uint flags = finalChunk ? BCRYPT_BLOCK_PADDING : 0;

        int status = BCryptDecrypt(
            keyHandle, input, inputLength, IntPtr.Zero, iv, iv.Length, output, output.Length, out outputLength, flags);

        CheckStatus(status, "BCryptDecrypt");
        return outputLength;
    }

    public static void Encrypt(string inputPath, string outputPath, string password, int bufferSize)
    {
        string tempPath = TempPath(outputPath);

        byte[] salt = new byte[SaltSize];
        byte[] iv = new byte[IvSize];
        byte[] encKey = null;
        byte[] macKey = null;

        IntPtr algorithm = IntPtr.Zero;
        IntPtr keyHandle = IntPtr.Zero;
        byte[] keyObject = null;

        bool success = false;

        try
        {
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);
            rng.GetBytes(iv);

            DeriveKeys(password, salt, out encKey, out macKey);

            algorithm = OpenAesAlgorithm();
            keyHandle = CreateAesKey(algorithm, encKey, out keyObject);

            using (FileStream input = OpenInput(inputPath))
            using (FileStream output = OpenOutput(tempPath))
            using (HMACSHA256 hmac = new HMACSHA256(macKey))
            {
                output.Write(Magic, 0, Magic.Length);
                output.Write(salt, 0, salt.Length);
                output.Write(iv, 0, iv.Length);

                byte[] zeroTag = new byte[TagSize];
                output.Write(zeroTag, 0, zeroTag.Length);
                Array.Clear(zeroTag, 0, zeroTag.Length);

                byte[] prefix = BuildMacPrefix(salt, iv);
                hmac.TransformBlock(prefix, 0, prefix.Length, prefix, 0);
                Array.Clear(prefix, 0, prefix.Length);

                byte[] inputBuffer = new byte[bufferSize];
                byte[] outputBuffer = new byte[bufferSize + AesBlockSize];
                byte[] ivState = (byte[])iv.Clone();

                while (true)
                {
                    int read = ReadUpTo(input, inputBuffer);

                    if (read == 0)
                    {
                        // File size is exactly a multiple of the block size, or the
                        // file is empty. We still need a full PKCS#7 padding block.
                        byte[] paddingBlock = new byte[AesBlockSize];
                        int padIndex;

                        for (padIndex = 0; padIndex < AesBlockSize; padIndex++)
                        {
                            paddingBlock[padIndex] = (byte)AesBlockSize;
                        }

                        int encrypted = EncryptChunk(keyHandle, paddingBlock, paddingBlock.Length, ivState, outputBuffer);
                        hmac.TransformBlock(outputBuffer, 0, encrypted, outputBuffer, 0);
                        output.Write(outputBuffer, 0, encrypted);

                        Array.Clear(paddingBlock, 0, paddingBlock.Length);
                        break;
                    }

                    bool finalPartial = read < inputBuffer.Length;
                    int plaintextLength = read;

                    if (finalPartial)
                    {
                        int padding = AesBlockSize - (plaintextLength % AesBlockSize);
                        if (padding == 0) padding = AesBlockSize;

                        int i;
                        for (i = 0; i < padding; i++)
                        {
                            inputBuffer[plaintextLength + i] = (byte)padding;
                        }

                        plaintextLength += padding;
                    }

                    int cipherLength = EncryptChunk(keyHandle, inputBuffer, plaintextLength, ivState, outputBuffer);
                    hmac.TransformBlock(outputBuffer, 0, cipherLength, outputBuffer, 0);
                    output.Write(outputBuffer, 0, cipherLength);

                    if (finalPartial) break;
                }

                hmac.TransformFinalBlock(new byte[0], 0, 0);
                byte[] tag = hmac.Hash;

                output.Position = MagicSize + SaltSize + IvSize;
                output.Write(tag, 0, tag.Length);
                output.Flush();
            }

            CommitTemp(tempPath, outputPath);

            success = true;
        }
        finally
        {
            if (keyHandle != IntPtr.Zero) BCryptDestroyKey(keyHandle);
            if (algorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(algorithm, 0);
            if (encKey != null) Array.Clear(encKey, 0, encKey.Length);
            if (macKey != null) Array.Clear(macKey, 0, macKey.Length);
            if (keyObject != null) Array.Clear(keyObject, 0, keyObject.Length);

            Array.Clear(salt, 0, salt.Length);
            Array.Clear(iv, 0, iv.Length);

            if (!success && File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { }
            }

        }
    }

    public static void Decrypt(string inputPath, string outputPath, string password, int bufferSize)
    {
        string tempPath = TempPath(outputPath);

        byte[] encKey = null;
        byte[] macKey = null;
        IntPtr algorithm = IntPtr.Zero;
        IntPtr keyHandle = IntPtr.Zero;
        byte[] keyObject = null;

        bool success = false;

        try
        {
            using (FileStream input = OpenInput(inputPath))
            {
                if (input.Length < HeaderSize + AesBlockSize)
                {
                    throw new InvalidDataException("File is too small to be a valid encrypted file.");
                }

                long ciphertextLength = input.Length - HeaderSize;

                if ((ciphertextLength % AesBlockSize) != 0)
                {
                    throw new InvalidDataException("Invalid ciphertext length.");
                }

                byte[] header = new byte[HeaderSize];
                ReadExactlyCount(input, header, header.Length);

                int i;
                for (i = 0; i < MagicSize; i++)
                {
                    if (header[i] != Magic[i])
                    {
                        throw new InvalidDataException("Unknown or incompatible file format.");
                    }
                }

                byte[] salt = new byte[SaltSize];
                byte[] iv = new byte[IvSize];
                byte[] expectedTag = new byte[TagSize];

                Buffer.BlockCopy(header, MagicSize, salt, 0, SaltSize);
                Buffer.BlockCopy(header, MagicSize + SaltSize, iv, 0, IvSize);
                Buffer.BlockCopy(header, MagicSize + SaltSize + IvSize, expectedTag, 0, TagSize);
                Array.Clear(header, 0, header.Length);

                try
                {
                    DeriveKeys(password, salt, out encKey, out macKey);

                    using (HMACSHA256 hmac = new HMACSHA256(macKey))
                    {
                        byte[] prefix = BuildMacPrefix(salt, iv);
                        hmac.TransformBlock(prefix, 0, prefix.Length, prefix, 0);
                        Array.Clear(prefix, 0, prefix.Length);

                        input.Position = HeaderSize;

                        byte[] buffer = new byte[bufferSize];
                        long remaining = ciphertextLength;

                        while (remaining > 0)
                        {
                            int wanted = (int)Math.Min((long)buffer.Length, remaining);
                            int read = ReadExactlyCount(input, buffer, wanted);
                            hmac.TransformBlock(buffer, 0, read, buffer, 0);
                            remaining -= read;
                        }

                        hmac.TransformFinalBlock(new byte[0], 0, 0);
                        byte[] actualTag = hmac.Hash;

                        if (!FixedTimeEquals(actualTag, expectedTag))
                        {
                            throw new CryptographicException("Incorrect password or modified/corrupted file.");
                        }

                        Array.Clear(buffer, 0, buffer.Length);
                    }

                    algorithm = OpenAesAlgorithm();
                    keyHandle = CreateAesKey(algorithm, encKey, out keyObject);

                    input.Position = HeaderSize;

                    byte[] ivState = (byte[])iv.Clone();
                    byte[] cipherBuffer = new byte[bufferSize];
                    byte[] plainBuffer = new byte[bufferSize + AesBlockSize];

                    using (FileStream output = OpenOutput(tempPath))
                    {
                        long remaining = ciphertextLength;

                        while (remaining > 0)
                        {
                            int wanted = (int)Math.Min((long)cipherBuffer.Length, remaining);
                            int read = ReadExactlyCount(input, cipherBuffer, wanted);

                            bool finalChunk = remaining == read;

                            int plainLength = DecryptChunk(
                                keyHandle, cipherBuffer, read, ivState, plainBuffer, finalChunk);

                            output.Write(plainBuffer, 0, plainLength);

                            remaining -= read;
                        }

                        output.Flush();
                    }

                    Array.Clear(cipherBuffer, 0, cipherBuffer.Length);
                    Array.Clear(plainBuffer, 0, plainBuffer.Length);
                }
                finally
                {
                    Array.Clear(salt, 0, salt.Length);
                    Array.Clear(iv, 0, iv.Length);
                    Array.Clear(expectedTag, 0, expectedTag.Length);
                }
            }

            CommitTemp(tempPath, outputPath);

            success = true;
        }
        finally
        {
            if (keyHandle != IntPtr.Zero) BCryptDestroyKey(keyHandle);
            if (algorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(algorithm, 0);
            if (encKey != null) Array.Clear(encKey, 0, encKey.Length);
            if (macKey != null) Array.Clear(macKey, 0, macKey.Length);
            if (keyObject != null) Array.Clear(keyObject, 0, keyObject.Length);

            if (!success && File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { }
            }

        }
    }
}
'@

    Add-Type -TypeDefinition $source -Language CSharp
}

# PowerShell interface
function Show-Usage {
    @"

  aes-cng.ps1 - Encrypt / decrypt files

  USAGE
    .\aes-cng.ps1 -Encrypt -In <file> -Out <file.enc>
    .\aes-cng.ps1 -Decrypt -In <file.enc> -Out <file>
    .\aes-cng.ps1 -h

  PARAMETERS
    -Encrypt          Encrypt the -In file into -Out
    -Decrypt          Decrypt the -In file into -Out
    -In <path>        Source file
    -Out <path>       Destination file
    -BufferSize <n>   I/O buffer size (default: 8 MB)
    -h, -Help         Show this help

  ENCRYPTION
    AES-256-CBC + HMAC-SHA256
    PBKDF2-HMAC-SHA256: 600000 iterations

  FORMAT
    [ Magic 8B ][ Salt 16B ][ IV 16B ][ HMAC 32B ][ Ciphertext ... ]

  CNG
    PBKDF2 and AES use Windows bcrypt.dll / CNG.

"@ | Write-Host
}

function Resolve-OutputPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }

    $currentPath = (Get-Location).ProviderPath
    $combinedPath = Join-Path $currentPath $Path

    return [IO.Path]::GetFullPath($combinedPath)
}

function Assert-DifferentPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputFile,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    $inFull = (Get-Item -LiteralPath $InputFile).FullName
    $outFull = Resolve-OutputPath $OutputFile

    if ([string]::Equals($inFull, $outFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The source file and the destination file must be different.'
    }
}

function Assert-OutputDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    $resolved = Resolve-OutputPath $OutputFile
    $dir = Split-Path -Parent $resolved

    if ([string]::IsNullOrEmpty($dir) -or $dir.Trim().Length -eq 0) {
        throw 'Invalid destination directory.'
    }

    if (-not [IO.Directory]::Exists($dir)) {
        throw "Destination directory does not exist: $dir"
    }
}

function Test-SecureStringEquals {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$A,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$B
    )

    $pa = [IntPtr]::Zero
    $pb = [IntPtr]::Zero
    $ba = $null
    $bb = $null
    $sa = $null
    $sb = $null

    try {
        $pa = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($A)
        $pb = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($B)

        $sa = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pa)
        $sb = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pb)

        $ba = [Text.Encoding]::Unicode.GetBytes($sa)
        $bb = [Text.Encoding]::Unicode.GetBytes($sb)

        $diff = $ba.Length -bxor $bb.Length
        $len = [Math]::Min($ba.Length, $bb.Length)

        for ($i = 0; $i -lt $len; $i++) {
            $diff = $diff -bor ($ba[$i] -bxor $bb[$i])
        }

        return ($diff -eq 0)
    }
    finally {
        if ($pa -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pa)
        }

        if ($pb -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pb)
        }

        if ($ba -ne $null) {
            [Array]::Clear($ba, 0, $ba.Length)
        }

        if ($bb -ne $null) {
            [Array]::Clear($bb, 0, $bb.Length)
        }

        $sa = $null
        $sb = $null
    }
}

function Assert-OperationInputs {
    param(
        [Parameter(Mandatory = $true)][string]$InputFile,
        [Parameter(Mandatory = $true)][string]$OutputFile,
        [Parameter(Mandatory = $true)][int]$Size
    )

    if (-not (Test-Path -LiteralPath $InputFile -PathType Leaf)) {
        throw "Source file not found: $InputFile"
    }
    if (($Size % 16) -ne 0) {
        throw 'BufferSize must be a multiple of 16.'
    }
    Assert-OutputDirectory -OutputFile $OutputFile
    Assert-DifferentPaths -InputFile $InputFile -OutputFile $OutputFile
}

function Get-PlainPassword {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Password
    )

    $ptr = [IntPtr]::Zero

    try {
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
}


# Main
switch ($PSCmdlet.ParameterSetName)
{
    'Help'
    {
        Show-Usage
    }

    'Encrypt'
    {
        try
        {
            Assert-OperationInputs -InputFile $In -OutputFile $Out -Size $BufferSize

            $pwd1 = Read-Host -AsSecureString 'Password'
            $pwd2 = Read-Host -AsSecureString 'Confirm password'

            if (-not (Test-SecureStringEquals -A $pwd1 -B $pwd2))
            {
                throw 'The two passwords do not match.'
            }

            $plainPwd = Get-PlainPassword -Password $pwd1

            try
            {
                [AesCngFileEngine]::Encrypt((Get-Item -LiteralPath $In).FullName, (Resolve-OutputPath $Out), $plainPwd, $BufferSize)
            }
            finally
            {
                $plainPwd = $null
            }

            Write-Host ""
            Write-Host ("Encrypted file: " + (Resolve-OutputPath $Out))
            Write-Host 'AES-256-CBC + HMAC-SHA256 | PBKDF2-HMAC-SHA256: 600000 iterations'
            Write-Host 'AES/PBKDF2 provider: Windows CNG / BCrypt'

        }
        catch
        {
            Write-Host ("Error: " + $_.Exception.Message) -ForegroundColor Red
            exit 1
        }
    }

    'Decrypt'
    {
        try
        {
            Assert-OperationInputs -InputFile $In -OutputFile $Out -Size $BufferSize

            $pwd = Read-Host -AsSecureString 'Password'
            $plainPwd = Get-PlainPassword -Password $pwd

            try
            {
                [AesCngFileEngine]::Decrypt((Get-Item -LiteralPath $In).FullName, (Resolve-OutputPath $Out), $plainPwd, $BufferSize)
            }
            finally
            {
                $plainPwd = $null
            }

            Write-Host ""
            Write-Host ("Decrypted and authenticated file: " + (Resolve-OutputPath $Out))
            Write-Host 'AES-256-CBC + HMAC-SHA256 | PBKDF2-HMAC-SHA256: 600000 iterations'
            Write-Host 'AES/PBKDF2 provider: Windows CNG / BCrypt'
        }
        catch
        {
            Write-Host ("Error: " + $_.Exception.Message) -ForegroundColor Red
            exit 1
        }
    }
}