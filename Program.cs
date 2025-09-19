using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Responses;
using Limilabs.Client.Authentication.Google;
using Limilabs.Client.IMAP;
using Limilabs.Mail;
using System.Security.Cryptography;

namespace GmailOAuthTest
{
    public class Program
    {
        // Simple In-Memory Token-"Store" für Demo
        static class TokenStore
        {
            public static TokenResponse? Token;
            public static DateTimeOffset? IssuedUtc;
        }

        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Fester Port für Redirect-URI
            builder.WebHost.UseUrls("http://localhost:5000");

            var cfg = builder.Configuration.GetSection("GoogleOAuth");
            var clientId = cfg["ClientId"] ?? throw new Exception("Google:ClientId fehlt");
            var clientSecret = cfg["ClientSecret"] ?? throw new Exception("Google:ClientSecret fehlt");
            var redirectUri = cfg["RedirectUri"] ?? "http://localhost:5000/oauth2callback";

            // Google OAuth2-Flow
            var flow = new GoogleAuthorizationCodeFlow(
                new GoogleAuthorizationCodeFlow.Initializer
                {
                    ClientSecrets = new ClientSecrets
                    {
                        ClientId = clientId,
                        ClientSecret = clientSecret
                    },
                    Scopes = new[]
                    {
                        "https://mail.google.com/" ,
                        "https://www.googleapis.com/auth/userinfo.email"
                    }
                });

            var app = builder.Build();

            app.MapGet("/", () =>
                Results.Content("""
                    <h1>Gmail OAuth2 IMAP Demo</h1>
                    <p><a href="/login">Login mit Google</a></p>
                    <p><a href="/fetch">Ungelesene Betreffzeilen abrufen</a></p>
                    <p>Redirect-URI: /oauth2callback</p>
                """, "text/html"));

            app.MapGet("/login", (HttpContext http) =>
            {
                var url = flow.CreateAuthorizationCodeRequest(redirectUri);
                var state = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
                http.Response.Cookies.Append("oauth_state", state, new CookieOptions { HttpOnly = true, Secure = false });
                url.State = state;
                return Results.Redirect(url.Build().ToString());
            });

            app.MapGet("/oauth2callback", async (HttpContext http, string? code, string? state) =>
            {
                var expected = http.Request.Cookies["oauth_state"];
                if (expected != null && state != expected) return Results.BadRequest("Ungültiger state");
                if (string.IsNullOrEmpty(code)) return Results.BadRequest("Kein Code");

                var token = await flow.ExchangeCodeForTokenAsync("", code, redirectUri, System.Threading.CancellationToken.None);

                TokenStore.Token = token;
                TokenStore.IssuedUtc = DateTimeOffset.UtcNow;

                return Results.Content("<p>OAuth erfolgreich. <a href=\"/fetch\">Jetzt Mails abrufen</a></p>", "text/html");
            });

            app.MapGet("/fetch", async (Microsoft.Extensions.Logging.ILogger<Program> log) =>
            {
                try
                {
                    if (TokenStore.Token == null)
                        return Results.BadRequest("Bitte zuerst /login aufrufen");

                    // Token ggf. refreshen
                    var token = TokenStore.Token;
                    bool needsRefresh =
                        token.RefreshToken != null &&
                        TokenStore.IssuedUtc.HasValue &&
                        TokenStore.IssuedUtc.Value.AddSeconds(token.ExpiresInSeconds ?? 0)
                            <= DateTimeOffset.UtcNow.AddMinutes(1);

                    if (needsRefresh)
                    {
                        token = await flow.RefreshTokenAsync("", token!.RefreshToken!, System.Threading.CancellationToken.None);
                        TokenStore.Token = token;
                        TokenStore.IssuedUtc = DateTimeOffset.UtcNow;
                    }

                    var accessToken = token!.AccessToken;

                    // E-Mail des Kontos holen
                    var api = new GoogleApi(accessToken);
                    var email = api.GetEmail();                 // wirft bei fehlendem Scope/invalidem Token

                    // IMAP: ungelesene Betreffzeilen
                    var subjects = new List<string>();
                    using (var imap = new Imap())
                    {
                        imap.ConnectSSL("imap.gmail.com");
                        imap.LoginOAUTH2(email, accessToken);   // wirft bei falschem Token/IMAP aus

                        imap.SelectInbox();
                        var uids = imap.Search(Flag.Unseen);
                        foreach (var uid in uids.Take(10))
                        {
                            var eml = imap.GetMessageByUID(uid);
                            var mail = new MailBuilder().CreateFromEml(eml);
                            subjects.Add(mail.Subject ?? "(kein Betreff)");
                        }
                        imap.Close();
                    }

                    return Results.Json(new { account = email, count = subjects.Count, subjects });
                }
                catch (Exception ex)
                {
                    // 500 sichtbar machen
                    log.LogError(ex, "Fehler in /fetch");
                    return Results.Problem(
                        title: "Fehler in /fetch",
                        detail: ex.Message,
                        statusCode: 500);
                }
            });

            app.Run();
        }
    }
}
