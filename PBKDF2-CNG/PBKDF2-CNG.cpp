#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <chrono>

#pragma comment(lib, "Bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

_Must_inspect_result_ NTSTATUS GenerateSalt(
    _Out_writes_bytes_all_(cbSalt) PUCHAR salt, 
    _In_ ULONG cbSalt)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // Open an algorithm handle for the RNG algorithm
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAlgorithm,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0
    )))
    {
        wprintf(L"Failed to open algorithm provider for RNG. Status: 0x%x\n", status);
        goto Cleanup;
    }

    // Generate the salt
    status = BCryptGenRandom(
        hAlgorithm,
        salt,
        cbSalt,
        0
    );

    if (!NT_SUCCESS(status))
    {
        wprintf(L"Failed to generate salt. Status: 0x%x\n", status);
    }

Cleanup:
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return status;
}

_Must_inspect_result_ NTSTATUS DeriveKeyUsingPBKDF2(
    _In_                                ULONG   iteration,
    _In_z_                              LPCWSTR password,
    _In_reads_bytes_(cbSalt)            PUCHAR  salt,
    _In_                                ULONG   cbSalt,
    _Out_writes_bytes_all_(cbDerived)   PUCHAR  derivedKey,
    _In_                                ULONG   cbDerived
)
{
    BCRYPT_ALG_HANDLE hHashAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // Open an algorithm handle for the PBKDF2 algorithm
    status = BCryptOpenAlgorithmProvider(
        &hHashAlg,
        BCRYPT_SHA512_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);

    if (!NT_SUCCESS(status)) {
        wprintf(L"Failed to open algorithm provider for PBKDF2. Status: 0x%x\n", status);
        goto Cleanup;
    }

    // Derive the key
    status = BCryptDeriveKeyPBKDF2(
        hHashAlg,
        (PUCHAR)password,
        (ULONG)(wcslen(password) * sizeof(WCHAR)),  
        salt,
        cbSalt,
        iteration,  
        derivedKey,
        cbDerived,
        0
    );

    if (!NT_SUCCESS(status))
    {
        wprintf(L"Failed to derive key. Status: 0x%x\n", status);
    }

Cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hHashAlg) BCryptCloseAlgorithmProvider(hHashAlg, 0);

    return status;
}

int main()
{
    // Example usage
    WCHAR password[24] = {};
    UCHAR salt[16] = {};  
    UCHAR derivedKey[64];

    wprintf(L"Enter a password: ");
    fgetws(password, _countof(password), stdin);

    auto start = std::chrono::high_resolution_clock::now();

    if (NT_SUCCESS(GenerateSalt(salt, sizeof(salt)))) 
    {
        if (NT_SUCCESS(DeriveKeyUsingPBKDF2(100000, password, salt, sizeof(salt), derivedKey, sizeof(derivedKey))))
        {
            wprintf(L"First byte of derived key: %02x\n", derivedKey[0]);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    wprintf(L"PBKDF2 execution time: %Idms\n", duration);

    return 0;
}
