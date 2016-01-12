using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Auth0.Windows
{
    /// <summary>
    /// A simple client to Authenticate Users with Auth0.
    /// </summary>
    public partial class Auth0Client
    {
        private const string AuthorizeUrl = "https://{0}/authorize?client_id={1}&redirect_uri={2}&response_type=token&connection={3}&scope={4}";
        private const string LogoutUrl = "https://{0}/logout?returnTo={1}";
        private const string LoginWidgetUrl = "https://{0}/login/?client={1}&redirect_uri={2}&response_type=token&scope={3}";
        private const string ResourceOwnerEndpoint = "https://{0}/oauth/ro";
        private const string DelegationEndpoint = "https://{0}/delegation";
        private const string UserInfoEndpoint = "https://{0}/userinfo?access_token={1}";
        private const string TokenInfoEndpoint = "https://{0}/tokeninfo";
        private const string DefaultCallback = "https://{0}/mobile";
        private const string DefaultLogoutCallback = "https://{0}/mobile/loggedout";

        private readonly string domain;
        private readonly string clientId;

        internal string State { get; set; }

        public Auth0Client(string domain, string clientId)
        {
            this.domain = domain;
            this.clientId = clientId;
        }

        public Auth0User CurrentUser { get; private set; }

        public string CallbackUrl
        {
            get
            {
                return string.Format(DefaultCallback, this.domain);
            }
        }

        /// <summary>
        /// Login a user into an Auth0 application by showing an embedded browser window either showing the widget or skipping it by passing a connection name
        /// </summary>
        /// <param name="owner">The owner window</param>
        /// <param name="connection">Optional connection name to bypass the login widget</param>
        /// <param name="scope">Optional. Scope indicating what attributes are needed. "openid" to just get the user_id or "openid profile" to get back everything.
        /// <remarks>When using openid profile if the user has many attributes the token might get big and the embedded browser (Internet Explorer) won't be able to parse a large URL</remarks>
        /// </param>
        /// <param name="device">If scope includes offline_access you must specify this parameter</param>
        /// <returns>Returns a Task of Auth0User</returns>
        public Task<Auth0User> LoginAsync(IWin32Window owner, string connection = "", string scope = "openid", string device = "")
        {
            var tcs = new TaskCompletionSource<Auth0User>();
            var auth = this.GetAuthenticator(connection, scope, device);

            auth.Error += (o, e) =>
            {
                var ex = e.Exception ?? new UnauthorizedAccessException(e.Message);
                tcs.TrySetException(ex);
            };

            auth.Canceled += (o, e) =>
            {
                tcs.TrySetCanceled();
            };
            auth.Completed += (o, e) =>
            {
                if (!e.IsAuthenticated)
                {
                    tcs.TrySetCanceled();
                }
                else
                {
                    if (this.State != e.Account.State)
                    {
                        tcs.TrySetException(new UnauthorizedAccessException("State does not match"));
                    }
                    else
                    {
                        this.SetupCurrentUser(e.Account);
                        tcs.TrySetResult(this.CurrentUser);
                    }
                }
            };

            auth.ShowUI(owner);

            return tcs.Task;
        }

        public Task<Auth0User> LoginAsync(string refreshToken, string scope = "openid")
        {
            return GetDelegationToken(null, new Dictionary<string, string>()
            {
                {"refresh_token", refreshToken},
                {"scope", "openid profile"}
            }).ContinueWith(t =>
            {
                try
                {
                    var data = t.Result.ToObject<Dictionary<string, string>>();

                    if (data.ContainsKey("error"))
                    {
                        throw new UnauthorizedAccessException("Error authenticating: " + data["error"]);
                    }
                    else if (data.ContainsKey("id_token"))
                    {
                        this.SetupCurrentUser(data["id_token"], refreshToken, int.Parse(data["expires_in"]));
                    }
                    else
                    {
                        throw new UnauthorizedAccessException("Expected access_token in access token response, but did not receive one.");
                    }
                }
                catch (Exception ex)
                {
                    throw ex;
                }
                return this.CurrentUser;
            });

        }


        /// <summary>
        ///  Log a user into an Auth0 application given an user name and password.
        /// </summary>
        /// <returns>Task that will complete when the user has finished authentication.</returns>
        /// <param name="connection" type="string">The name of the connection to use in Auth0. Connection defines an Identity Provider.</param>
        /// <param name="userName" type="string">User name.</param>
        /// <param name="password" type="string">User password.</param>
        /// <param name="scope">Optional. Scope indicating what attributes are needed. "openid" to just get the user id or "openid profile" to get back everything.
        /// </param>
        /// <param name="device">If scope includes offline_access you must specify this parameter</param>
        public Task<Auth0User> LoginAsync(string connection, string userName, string password, string scope = "openid", string device = "")
        {
            var endpoint = string.Format(ResourceOwnerEndpoint, this.domain);
            var parameters = new Dictionary<string, string> 
			{
				{ "client_id", this.clientId },
				{ "connection", connection },
				{ "username", userName },
				{ "password", password },
				{ "grant_type", "password" },
				{ "scope", scope },
                { "device", device }
			};

            var request = new HttpClient();
            return request.PostAsync(new Uri(endpoint), new FormUrlEncodedContent(parameters)).ContinueWith(t =>
            {
                try
                {
                    t.Result.EnsureSuccessStatusCode();
                    var text = t.Result.Content.ReadAsStringAsync().Result;
                    var data = JObject.Parse(text).ToObject<Dictionary<string, string>>();

                    if (data.ContainsKey("error"))
                    {
                        throw new UnauthorizedAccessException("Error authenticating: " + data["error"]);
                    }
                    else if (data.ContainsKey("access_token"))
                    {
                        this.SetupCurrentUser(data);
                    }
                    else
                    {
                        throw new UnauthorizedAccessException("Expected access_token in access token response, but did not receive one.");
                    }
                }
                catch (Exception ex)
                {
                    throw ex;
                }

                return this.CurrentUser;
            });
        }

        /// <summary>
        /// Get a delegation token.
        /// </summary>
        /// <returns>Delegation token result.</returns>
        /// <param name="targetClientId">Target client ID.</param>
        /// <param name="options">Custom parameters.</param>
        public Task<JObject> GetDelegationToken(string targetClientId, IDictionary<string, string> options = null)
        {
            string idToken = "";
            options = options ?? new Dictionary<string, string>();

            // ensure id_token
            if (options.ContainsKey("id_token"))
            {
                idToken = options["id_token"];
                options.Remove("id_token");
            }
            else if(targetClientId != null)
            {
                idToken = this.CurrentUser?.IdToken;
                if (string.IsNullOrEmpty(idToken))
                {
                    throw new InvalidOperationException(
                        "You need to login first or specify a value for id_token parameter.");
                }
            }
            

            var endpoint = string.Format(DelegationEndpoint, this.domain);
            var parameters = new Dictionary<string, string> 
            {
                { "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
                { "client_id", this.clientId }
            };
            if (targetClientId != null)
            {
                parameters.Add("id_token", idToken);
                parameters.Add("target", targetClientId);
            }

            // custom parameters
            foreach (var option in options)
            {
                parameters.Add(option.Key, option.Value);
            }

            var request = new HttpClient();
            return request.PostAsync(new Uri(endpoint), new FormUrlEncodedContent(parameters)).ContinueWith(t =>
            {
                try
                {
                    var text = t.Result.Content.ReadAsStringAsync().Result;
                    return JObject.Parse(text);
                }
                catch (Exception)
                {
                    throw;
                }
            });
        }

        public void Logout(IWin32Window owner)
        {
            this.CurrentUser = null;

            var auth = this.GetAuthenticator("", "openid", "");

            //auth.Error += (o, e) =>
            //{
            //    var ex = e.Exception ?? new UnauthorizedAccessException(e.Message);
            //    tcs.TrySetException(ex);
            //};
            //auth.Canceled += (o, e) =>
            //{
            //    tcs.TrySetCanceled();
            //};
            //auth.Completed += (o, e) =>
            //{
            //    tcs.TrySetResult(true);
            //};
            auth.ShowLogoutUI(owner);
        }

        private void SetupCurrentUser(Auth0User auth0User)
        {
            if (auth0User.Profile != null)
            {
                this.CurrentUser = auth0User;
            }
            else
            {
                this.SetupCurrentUser(new Dictionary<string, string> 
                {
                    { "access_token", auth0User.Auth0AccessToken },
                    { "refresh_token", auth0User.RefreshToken },
                    { "id_token", auth0User.IdToken },
                    { "state", auth0User.State }
                });
            }
        }


        private void SetupCurrentUser(string idToken, string refreshToken, int expiresIn)
        {
            var endpoint = string.Format(TokenInfoEndpoint, this.domain);
            var request = new HttpClient();

            request.PostAsync(new Uri(endpoint), new FormUrlEncodedContent(new Dictionary<string,string>() { { "id_token", idToken } })).ContinueWith(t =>
            {
                var accountProperties = new Dictionary<string, string>();
                accountProperties["refresh_token"] = refreshToken;
                accountProperties["id_token"] = idToken;
                try
                {
                    t.Result.EnsureSuccessStatusCode();
                    var profileString = t.Result.Content.ReadAsStringAsync().Result;
                    accountProperties.Add("profile", profileString);
                }
                catch (Exception ex)
                {
                    throw ex;
                }
                finally
                {
                    this.SetupCurrentUser(new Auth0User(accountProperties)
                    {
                        IdTokenExpiresAt = DateTime.Now.AddSeconds(expiresIn)
                    });
                }
            })
            .Wait();
        }

        private void SetupCurrentUser(IDictionary<string, string> accountProperties)
        {
            var endpoint = string.Format(UserInfoEndpoint, this.domain, accountProperties["access_token"]);
            var request = new HttpClient();

            request.GetAsync(new Uri(endpoint)).ContinueWith(t =>
            {
                try
                {
                    t.Result.EnsureSuccessStatusCode();
                    var profileString = t.Result.Content.ReadAsStringAsync().Result;
                    accountProperties.Add("profile", profileString);
                }
                catch (Exception ex)
                {
                    throw ex;
                }
                finally
                {
                    this.CurrentUser = new Auth0User(accountProperties);
                }
            })
            .Wait();
        }

        protected virtual BrowserAuthenticationForm GetAuthenticator(string connection, string scope, string device)
        {
            // Generate state to include in startUri
            var chars = new char[16];
            var rand = new Random();
            for (var i = 0; i < chars.Length; i++)
            {
                chars[i] = (char)rand.Next((int)'a', (int)'z' + 1);
            }

            var redirectUri = this.CallbackUrl;
            var authorizeUri = !string.IsNullOrWhiteSpace(connection) ?
                string.Format(AuthorizeUrl, this.domain, this.clientId, Uri.EscapeDataString(redirectUri), connection, scope) :
                string.Format(LoginWidgetUrl, this.domain, this.clientId, Uri.EscapeDataString(redirectUri), scope);

            if (!string.IsNullOrWhiteSpace(device))
            {
                authorizeUri += $"&device={device}";
            }
            this.State = new string(chars);
            var startUri = new Uri($"{authorizeUri}&state={this.State}");
            var endUri = new Uri(redirectUri);

            var logoutEndRedirect = string.Format(DefaultLogoutCallback, this.domain);
            var logoutStartUri = new Uri(string.Format(LogoutUrl, this.domain, logoutEndRedirect));
            var logoutEndUri = new Uri(logoutEndRedirect);


            var auth = new BrowserAuthenticationForm(startUri, endUri, logoutStartUri, logoutEndUri);

            return auth;
        }
    }
}
