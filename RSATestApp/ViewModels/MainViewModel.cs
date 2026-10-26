using RSATestApp.Services;

namespace RSATestApp.ViewModels;

public sealed class MainViewModel : BaseViewModel
{
    private readonly AuthClient _authClient;

    private string _serverUrl = DeviceInfo.Platform == DevicePlatform.Android
        ? "http://10.0.2.2:5000"     // emulator will not see localhost of host machine, use special IP instead
        : "http://localhost:5000";
    private string _login = "student";
    private string _password = string.Empty;
    private string _statusText = string.Empty;
    private bool _isSuccess;
    private bool _isBusy;
    private bool _hasTrace;
    private string _publicKeyText = string.Empty;
    private string _plainText = string.Empty;
    private string _cipherText = string.Empty;

    public MainViewModel(AuthClient authClient)
    {
        _authClient = authClient;
        LoginCommand = new Command(async () => await LoginAsync(), () => !IsBusy);
    }

    public Command LoginCommand { get; }

    public string ServerUrl
    {
        get => _serverUrl;
        set => SetProperty(ref _serverUrl, value);
    }

    public string Login
    {
        get => _login;
        set => SetProperty(ref _login, value);
    }

    public string Password
    {
        get => _password;
        set => SetProperty(ref _password, value);
    }

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public bool IsSuccess
    {
        get => _isSuccess;
        set => SetProperty(ref _isSuccess, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
                LoginCommand.ChangeCanExecute(); 
        }
    }

    public bool HasTrace
    {
        get => _hasTrace;
        set => SetProperty(ref _hasTrace, value);
    }

    public string PublicKeyText
    {
        get => _publicKeyText;
        set => SetProperty(ref _publicKeyText, value);
    }

    public string PlainText
    {
        get => _plainText;
        set => SetProperty(ref _plainText, value);
    }

    public string CipherText
    {
        get => _cipherText;
        set => SetProperty(ref _cipherText, value);
    }

    private async Task LoginAsync()
    {
        IsBusy = true;
        StatusText = string.Empty;

        try
        {
            var trace = await _authClient.LoginAsync(ServerUrl, Login, Password);

            IsSuccess = trace.Response.Success;
            StatusText = trace.Response.Message;

            PublicKeyText = $"E = {trace.PublicKey.E}\n" +
                            $"N ({trace.PublicKey.N.GetBitLength()} bits) = {Shorten(trace.PublicKey.N.ToString())}";
            PlainText = trace.PlainJson;
            CipherText = $"Blocks: {trace.Blocks.Length}, Encryption: {trace.EncryptMs:F2} ms\n\n" +
                         string.Join("\n\n", trace.Blocks.Select(Shorten));
            HasTrace = true;
        }
        catch (HttpRequestException ex)
        {
            ShowError($"Server unavailable: {ex.Message}");
        }
        catch (TaskCanceledException)
        {
            ShowError("Server did not respond in time");
        }
        catch (Exception ex)
        {
            ShowError($"Error: {ex.Message}");
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ShowError(string message)
    {
        IsSuccess = false;
        StatusText = message;
        HasTrace = false;
    }

    private static string Shorten(string s) => s.Length > 80 ? $"{s[..40]}…{s[^40..]}" : s;
}