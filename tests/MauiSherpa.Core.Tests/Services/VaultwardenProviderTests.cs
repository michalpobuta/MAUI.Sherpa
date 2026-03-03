using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MauiSherpa.Core.Interfaces;
using MauiSherpa.Core.Services;

namespace MauiSherpa.Core.Tests.Services;

public class VaultwardenProviderTests
{
    #region Test Helpers

    private static VaultwardenProvider CreateProvider(Dictionary<string, string>? settings = null)
    {
        var config = new CloudSecretsProviderConfig(
            "test-id", "test", CloudSecretsProviderType.Vaultwarden,
            settings ?? new Dictionary<string, string>());
        return new VaultwardenProvider(config, new MockLoggingService());
    }

    /// <summary>
    /// Create a test encryption key pair for crypto tests.
    /// </summary>
    private static (byte[] EncKey, byte[] MacKey) GenerateTestKeys()
    {
        var encKey = RandomNumberGenerator.GetBytes(32);
        var macKey = RandomNumberGenerator.GetBytes(32);
        return (encKey, macKey);
    }

    #endregion

    #region Key Derivation Tests

    [Fact]
    public void DeriveKey_ProducesConsistentOutput()
    {
        // Same inputs should produce same key
        var key1 = VaultwardenProvider.DeriveKey("p4ssw0rd", "nobody@example.com", 5000);
        var key2 = VaultwardenProvider.DeriveKey("p4ssw0rd", "nobody@example.com", 5000);
        Assert.Equal(key1, key2);
    }

    [Fact]
    public void DeriveKey_ProducesDifferentKeysForDifferentPasswords()
    {
        var key1 = VaultwardenProvider.DeriveKey("password1", "test@example.com", 5000);
        var key2 = VaultwardenProvider.DeriveKey("password2", "test@example.com", 5000);
        Assert.NotEqual(key1, key2);
    }

    [Fact]
    public void DeriveKey_ProducesDifferentKeysForDifferentSalts()
    {
        var key1 = VaultwardenProvider.DeriveKey("password", "user1@example.com", 5000);
        var key2 = VaultwardenProvider.DeriveKey("password", "user2@example.com", 5000);
        Assert.NotEqual(key1, key2);
    }

    [Fact]
    public void DeriveKey_Produces32Bytes()
    {
        var key = VaultwardenProvider.DeriveKey("password", "test@example.com", 5000);
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public void HashPassword_ProducesBase64String()
    {
        var masterKey = VaultwardenProvider.DeriveKey("p4ssw0rd", "nobody@example.com", 5000);
        var hash = VaultwardenProvider.HashPassword(masterKey, "p4ssw0rd");

        // Should be valid base64
        Assert.NotNull(hash);
        var decoded = Convert.FromBase64String(hash);
        Assert.Equal(32, decoded.Length);
    }

    [Fact]
    public void HashPassword_ConsistentOutput()
    {
        var masterKey = VaultwardenProvider.DeriveKey("p4ssw0rd", "nobody@example.com", 5000);
        var hash1 = VaultwardenProvider.HashPassword(masterKey, "p4ssw0rd");
        var hash2 = VaultwardenProvider.HashPassword(masterKey, "p4ssw0rd");
        Assert.Equal(hash1, hash2);
    }

    #endregion

    #region AES Encryption/Decryption Tests

    [Fact]
    public void AesEncryptDecrypt_Roundtrip()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(16);
        var plainText = Encoding.UTF8.GetBytes("Hello, Bitwarden!");

        var encrypted = VaultwardenProvider.AesEncrypt(plainText, key, iv);
        var decrypted = VaultwardenProvider.AesDecrypt(encrypted, key, iv);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void AesEncryptDecrypt_EmptyString()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(16);
        var plainText = Encoding.UTF8.GetBytes("");

        var encrypted = VaultwardenProvider.AesEncrypt(plainText, key, iv);
        var decrypted = VaultwardenProvider.AesDecrypt(encrypted, key, iv);

        Assert.Equal(plainText, decrypted);
    }

    [Fact]
    public void AesEncryptDecrypt_BinaryData()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(16);
        var plainText = new byte[] { 0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F };

        var encrypted = VaultwardenProvider.AesEncrypt(plainText, key, iv);
        var decrypted = VaultwardenProvider.AesDecrypt(encrypted, key, iv);

        Assert.Equal(plainText, decrypted);
    }

    #endregion

    #region CipherString Encrypt/Decrypt Tests

    [Fact]
    public void EncryptString_ProducesType2CipherString()
    {
        var (encKey, macKey) = GenerateTestKeys();
        var cipher = VaultwardenProvider.EncryptString("test value", encKey, macKey);

        Assert.StartsWith("2.", cipher);
        var parts = cipher[2..].Split('|');
        Assert.Equal(3, parts.Length); // IV | CT | MAC
    }

    [Fact]
    public void EncryptDecryptString_Roundtrip()
    {
        var (encKey, macKey) = GenerateTestKeys();
        var original = "Hello, World! Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?";

        var encrypted = VaultwardenProvider.EncryptString(original, encKey, macKey);
        var decrypted = VaultwardenProvider.DecryptString(encrypted, encKey, macKey);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void EncryptDecryptString_Unicode()
    {
        var (encKey, macKey) = GenerateTestKeys();
        var original = "Unicode: 日本語 中文 한국어 🎉";

        var encrypted = VaultwardenProvider.EncryptString(original, encKey, macKey);
        var decrypted = VaultwardenProvider.DecryptString(encrypted, encKey, macKey);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void EncryptDecryptString_EmptyString()
    {
        var (encKey, macKey) = GenerateTestKeys();
        var original = "";

        var encrypted = VaultwardenProvider.EncryptString(original, encKey, macKey);
        var decrypted = VaultwardenProvider.DecryptString(encrypted, encKey, macKey);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void DecryptString_InvalidMac_Throws()
    {
        var (encKey, macKey) = GenerateTestKeys();
        var encrypted = VaultwardenProvider.EncryptString("test", encKey, macKey);

        // Tamper with the MAC
        var parts = encrypted[2..].Split('|');
        var tamperedMac = Convert.FromBase64String(parts[2]);
        tamperedMac[0] ^= 0xFF;
        var tampered = $"2.{parts[0]}|{parts[1]}|{Convert.ToBase64String(tamperedMac)}";

        Assert.Throws<CryptographicException>(() =>
            VaultwardenProvider.DecryptString(tampered, encKey, macKey));
    }

    #endregion

    #region MAC Tests

    [Fact]
    public void ComputeMac_ConsistentOutput()
    {
        var macKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(16);
        var ct = RandomNumberGenerator.GetBytes(48);

        var mac1 = VaultwardenProvider.ComputeMac(macKey, iv, ct);
        var mac2 = VaultwardenProvider.ComputeMac(macKey, iv, ct);

        Assert.Equal(mac1, mac2);
    }

    [Fact]
    public void VerifyMac_ValidMac_DoesNotThrow()
    {
        var macKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(16);
        var ct = RandomNumberGenerator.GetBytes(48);
        var mac = VaultwardenProvider.ComputeMac(macKey, iv, ct);

        // Should not throw
        VaultwardenProvider.VerifyMac(macKey, iv, ct, mac);
    }

    [Fact]
    public void VerifyMac_InvalidMac_Throws()
    {
        var macKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(16);
        var ct = RandomNumberGenerator.GetBytes(48);
        var badMac = RandomNumberGenerator.GetBytes(32);

        Assert.Throws<CryptographicException>(() =>
            VaultwardenProvider.VerifyMac(macKey, iv, ct, badMac));
    }

    #endregion

    #region HKDF Stretch Tests

    [Fact]
    public void HkdfStretch_Produces64Bytes()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var stretched = VaultwardenProvider.HkdfStretch(key);
        Assert.Equal(64, stretched.Length);
    }

    [Fact]
    public void HkdfStretch_ConsistentOutput()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var s1 = VaultwardenProvider.HkdfStretch(key);
        var s2 = VaultwardenProvider.HkdfStretch(key);
        Assert.Equal(s1, s2);
    }

    [Fact]
    public void HkdfStretch_EncAndMacKeysDiffer()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var stretched = VaultwardenProvider.HkdfStretch(key);
        var encPart = stretched[..32];
        var macPart = stretched[32..];
        Assert.NotEqual(encPart, macPart);
    }

    #endregion

    #region Protected Key Decryption Tests

    [Fact]
    public void DecryptProtectedKey_Type0_Works()
    {
        // Create a known symmetric key (64 bytes)
        var symmetricKey = RandomNumberGenerator.GetBytes(64);
        var masterKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(16);

        // Encrypt it as type 0 (AesCbc256_B64)
        var ct = VaultwardenProvider.AesEncrypt(symmetricKey, masterKey, iv);
        var protectedKey = $"0.{Convert.ToBase64String(iv)}|{Convert.ToBase64String(ct)}";

        var provider = CreateProvider();
        provider.DecryptProtectedKey(protectedKey, masterKey);

        // Verify we can access internal keys (via encrypt/decrypt roundtrip)
        // The provider should have set _encKey and _macKey
        // Test by using EncryptString which requires valid keys
    }

    [Fact]
    public void DecryptProtectedKey_Type2_Works()
    {
        // Create a known symmetric key (64 bytes)
        var symmetricKey = RandomNumberGenerator.GetBytes(64);
        var masterKey = RandomNumberGenerator.GetBytes(32);

        // Stretch the master key for type 2
        var stretchedKey = VaultwardenProvider.HkdfStretch(masterKey);
        var stretchEncKey = stretchedKey[..32];
        var stretchMacKey = stretchedKey[32..];

        var iv = RandomNumberGenerator.GetBytes(16);
        var ct = VaultwardenProvider.AesEncrypt(symmetricKey, stretchEncKey, iv);
        var mac = VaultwardenProvider.ComputeMac(stretchMacKey, iv, ct);
        var protectedKey = $"2.{Convert.ToBase64String(iv)}|{Convert.ToBase64String(ct)}|{Convert.ToBase64String(mac)}";

        var provider = CreateProvider();
        provider.DecryptProtectedKey(protectedKey, masterKey);
    }

    [Fact]
    public void DecryptProtectedKey_UnsupportedType_Throws()
    {
        var protectedKey = "3.dGVzdA==|dGVzdA==|dGVzdA==";
        var masterKey = RandomNumberGenerator.GetBytes(32);
        var provider = CreateProvider();

        Assert.Throws<NotSupportedException>(() =>
            provider.DecryptProtectedKey(protectedKey, masterKey));
    }

    #endregion

    #region SetField / RemoveField Tests

    [Fact]
    public void SetField_AddsNewField()
    {
        var fields = new List<Dictionary<string, object?>>();
        VaultwardenProvider.SetField(fields, "new-key", "new-value");

        Assert.Single(fields);
        Assert.Equal("new-key", fields[0]["name"]);
        Assert.Equal("new-value", fields[0]["value"]);
        Assert.Equal(1, fields[0]["type"]); // Hidden type
    }

    [Fact]
    public void SetField_UpdatesExistingField()
    {
        var fields = new List<Dictionary<string, object?>>
        {
            new() { ["name"] = "my-key", ["value"] = "old-value", ["type"] = 1 }
        };

        VaultwardenProvider.SetField(fields, "my-key", "new-value");

        Assert.Single(fields);
        Assert.Equal("new-value", fields[0]["value"]);
    }

    [Fact]
    public void SetField_UpdateIsCaseInsensitive()
    {
        var fields = new List<Dictionary<string, object?>>
        {
            new() { ["name"] = "My-Key", ["value"] = "old-value", ["type"] = 1 }
        };

        VaultwardenProvider.SetField(fields, "my-key", "new-value");

        Assert.Single(fields); // Should update, not add
        Assert.Equal("new-value", fields[0]["value"]);
    }

    [Fact]
    public void RemoveField_RemovesExistingField()
    {
        var fields = new List<Dictionary<string, object?>>
        {
            new() { ["name"] = "key1", ["value"] = "val1", ["type"] = 1 },
            new() { ["name"] = "key2", ["value"] = "val2", ["type"] = 1 }
        };

        var removed = VaultwardenProvider.RemoveField(fields, "key1");

        Assert.True(removed);
        Assert.Single(fields);
        Assert.Equal("key2", fields[0]["name"]);
    }

    [Fact]
    public void RemoveField_ReturnsFalseWhenNotFound()
    {
        var fields = new List<Dictionary<string, object?>>
        {
            new() { ["name"] = "key1", ["value"] = "val1", ["type"] = 1 }
        };

        var removed = VaultwardenProvider.RemoveField(fields, "nonexistent");

        Assert.False(removed);
        Assert.Single(fields);
    }

    [Fact]
    public void RemoveField_IsCaseInsensitive()
    {
        var fields = new List<Dictionary<string, object?>>
        {
            new() { ["name"] = "My-Key", ["value"] = "val1", ["type"] = 1 }
        };

        var removed = VaultwardenProvider.RemoveField(fields, "my-key");
        Assert.True(removed);
        Assert.Empty(fields);
    }

    #endregion

    #region Base64 Roundtrip Tests

    [Theory]
    [InlineData("Hello, World!")]
    [InlineData("")]
    [InlineData("Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?")]
    [InlineData("Unicode: 日本語 中文 한국어")]
    public void Base64Roundtrip_PreservesData(string original)
    {
        var bytes = Encoding.UTF8.GetBytes(original);
        var base64 = Convert.ToBase64String(bytes);
        var restored = Convert.FromBase64String(base64);
        Assert.Equal(bytes, restored);
    }

    [Fact]
    public void Base64Roundtrip_BinaryData()
    {
        var bytes = new byte[] { 0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F };
        var base64 = Convert.ToBase64String(bytes);
        var restored = Convert.FromBase64String(base64);
        Assert.Equal(bytes, restored);
    }

    #endregion

    #region Server URL Resolution Tests

    [Fact]
    public void ServerUrl_BitwardenMode_ReturnsBitwardenCloud()
    {
        var provider = CreateProvider(new Dictionary<string, string>
        {
            ["ServerMode"] = "bitwarden",
            ["ServerUrl"] = "https://custom.example.com"
        });
        Assert.Equal(VaultwardenProvider.BitwardenCloudUrl, provider.ServerUrl);
    }

    [Fact]
    public void ServerUrl_VaultwardenMode_ReturnsVaultwardenNet()
    {
        var provider = CreateProvider(new Dictionary<string, string>
        {
            ["ServerMode"] = "vaultwarden",
            ["ServerUrl"] = "https://custom.example.com"
        });
        Assert.Equal(VaultwardenProvider.VaultwardenNetUrl, provider.ServerUrl);
    }

    [Fact]
    public void ServerUrl_CustomMode_ReturnsCustomUrl()
    {
        var provider = CreateProvider(new Dictionary<string, string>
        {
            ["ServerMode"] = "custom",
            ["ServerUrl"] = "https://my-vault.example.com"
        });
        Assert.Equal("https://my-vault.example.com", provider.ServerUrl);
    }

    [Fact]
    public void ServerUrl_DefaultMode_UsesCustom()
    {
        var provider = CreateProvider(new Dictionary<string, string>
        {
            ["ServerUrl"] = "https://my-vault.example.com"
        });
        Assert.Equal("https://my-vault.example.com", provider.ServerUrl);
    }

    [Fact]
    public void ServerUrl_TrimsTrailingSlash()
    {
        var provider = CreateProvider(new Dictionary<string, string>
        {
            ["ServerMode"] = "custom",
            ["ServerUrl"] = "https://my-vault.example.com/"
        });
        Assert.Equal("https://my-vault.example.com", provider.ServerUrl);
    }

    #endregion

    #region Provider Properties Tests

    [Fact]
    public void ProviderType_ReturnsVaultwarden()
    {
        var provider = CreateProvider();
        Assert.Equal(CloudSecretsProviderType.Vaultwarden, provider.ProviderType);
    }

    [Fact]
    public void DisplayName_ReturnsExpected()
    {
        var provider = CreateProvider();
        Assert.Equal("Vaultwarden / Bitwarden", provider.DisplayName);
    }

    #endregion

    #region Factory Integration Tests

    [Fact]
    public void Factory_SupportsVaultwarden()
    {
        var factory = new CloudSecretsProviderFactory(new MockLoggingService());
        Assert.Contains(CloudSecretsProviderType.Vaultwarden, factory.SupportedProviders);
    }

    [Fact]
    public void Factory_GetProviderSettings_ReturnsVaultwardenSettings()
    {
        var factory = new CloudSecretsProviderFactory(new MockLoggingService());
        var settings = factory.GetProviderSettings(CloudSecretsProviderType.Vaultwarden);
        Assert.NotNull(settings);
        Assert.True(settings.Count >= 6);
        Assert.Contains(settings, s => s.Key == "ServerMode");
        Assert.Contains(settings, s => s.Key == "ServerUrl");
        Assert.Contains(settings, s => s.Key == "Email");
        Assert.Contains(settings, s => s.Key == "ClientId");
        Assert.Contains(settings, s => s.Key == "ClientSecret" && s.IsSecret);
        Assert.Contains(settings, s => s.Key == "MasterPassword" && s.IsSecret);
        Assert.Contains(settings, s => s.Key == "ItemName");
    }

    [Fact]
    public void Factory_ServerMode_HasOptions()
    {
        var factory = new CloudSecretsProviderFactory(new MockLoggingService());
        var settings = factory.GetProviderSettings(CloudSecretsProviderType.Vaultwarden);
        var serverMode = settings.First(s => s.Key == "ServerMode");

        Assert.NotNull(serverMode.Options);
        Assert.Equal(3, serverMode.Options.Length);
        Assert.Contains(serverMode.Options, o => o.StartsWith("bitwarden"));
        Assert.Contains(serverMode.Options, o => o.StartsWith("vaultwarden"));
        Assert.Contains(serverMode.Options, o => o.StartsWith("custom"));
    }

    [Fact]
    public void Factory_ServerUrl_DependsOnServerMode()
    {
        var factory = new CloudSecretsProviderFactory(new MockLoggingService());
        var settings = factory.GetProviderSettings(CloudSecretsProviderType.Vaultwarden);
        var serverUrl = settings.First(s => s.Key == "ServerUrl");

        Assert.Equal("ServerMode", serverUrl.DependsOn);
        Assert.Equal("custom", serverUrl.DependsOnValue);
    }

    [Fact]
    public void Factory_GetProviderDisplayName_ReturnsVaultwardenName()
    {
        var factory = new CloudSecretsProviderFactory(new MockLoggingService());
        var name = factory.GetProviderDisplayName(CloudSecretsProviderType.Vaultwarden);
        Assert.Equal("Vaultwarden / Bitwarden", name);
    }

    #endregion

    #region Mock

    private class MockLoggingService : ILoggingService
    {
        public string? LogFilePath => null;
        public void LogInformation(string message) { }
        public void LogWarning(string message) { }
        public void LogError(string message, Exception? exception = null) { }
        public void LogDebug(string message) { }
        public IReadOnlyList<LogEntry> GetRecentLogs(int maxCount = 500) => Array.Empty<LogEntry>();
        public void ClearLogs() { }
        public event Action? OnLogAdded;
    }

    #endregion
}
