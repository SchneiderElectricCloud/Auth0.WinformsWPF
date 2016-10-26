using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Newtonsoft.Json.Linq;

namespace Auth0.Windows
{
    public class Auth0User
    {
        public Auth0User()
        {
        }

        public Auth0User(IDictionary<string, string> accountProperties)
        {
            this.Auth0AccessToken = accountProperties.ContainsKey("access_token") ? accountProperties["access_token"] : string.Empty;
            this.IdToken = accountProperties.ContainsKey("id_token") ? accountProperties["id_token"] : string.Empty;
            this.Profile = accountProperties.ContainsKey("profile") ? accountProperties["profile"].ToJson() : null;
            this.RefreshToken = accountProperties.ContainsKey("refresh_token") ? accountProperties["refresh_token"] : string.Empty;

            this.State = accountProperties.ContainsKey("state") ? accountProperties["state"] : null;
            if (this.Profile?["exp"] != null)
            {
                this.IdTokenExpiresAt = UnixTimeStampToDateTime(double.Parse(this.Profile["exp"].ToString()));
            }
            else
            {
                var token = new JwtSecurityToken(this.IdToken);
                this.IdTokenExpiresAt = token.ValidTo;
            } 
        }

        public string RefreshToken { get; set; }

        public string Auth0AccessToken { get; set; }

        public string IdToken { get; set; }

        public DateTime IdTokenExpiresAt { get; set; }

        public JObject Profile { get; set; }

        public string State { get; set; }

        internal static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToLocalTime();
            return dtDateTime;
        }
    }

    internal static class Extensions
    {
        internal static JObject ToJson(this string jsonString)
        {
            return JObject.Parse(jsonString);
        }
    }
}