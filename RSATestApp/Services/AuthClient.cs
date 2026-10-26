using RSAGen;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using static RSAGen.DTOs;

namespace RSATestApp.Services;

public sealed record LoginTrace(
    RsaPublicKey PublicKey,
    string PlainJson,
    string[] Blocks,
    double EncryptMs,
    LoginResponse Response);

public sealed class AuthClient(HttpClient http)
{
    public async Task<LoginTrace> LoginAsync(string serverUrl, string login, string password, CancellationToken ct = default)
    {
        var baseUri = new Uri(serverUrl.TrimEnd('/') + "/");

        // 1. Public key
        var keyDto = await http.GetFromJsonAsync<PublicKeyDto>(new Uri(baseUri, "api/keys/public"), ct)
                     ?? throw new InvalidOperationException("No public key received");
        var publicKey = new RsaPublicKey(keyDto.E.FromBase64(), keyDto.N.FromBase64());

        // 2. Object → bytes → encryption
        byte[] plain = JsonSerializer.SerializeToUtf8Bytes(new LoginRequest(login, password));

        var sw = Stopwatch.StartNew();
        var encrypted = RSAKey.Encrypt(plain, publicKey);
        sw.Stop();

        string[] blocks = encrypted.Select(b => b.ToBase64()).ToArray();

        // 3. Sending
        using var response = await http.PostAsJsonAsync(
            new Uri(baseUri, "api/auth/login"), new EncryptedLoginDto(blocks), ct);

        var body = await TryReadResponse(response, ct)
                   ?? new LoginResponse(false, $"HTTP {(int)response.StatusCode}");

        return new LoginTrace(publicKey, Encoding.UTF8.GetString(plain), blocks, sw.Elapsed.TotalMilliseconds, body);
    }

    private static async Task<LoginResponse?> TryReadResponse(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<LoginResponse>(ct);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            return null; // body is empty or not JSON
        }
    }
}
