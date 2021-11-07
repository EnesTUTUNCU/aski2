using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using askiapp.Model;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;

namespace askiapp.Security
{
    public class AuthStateProvider : AuthenticationStateProvider
    {
        private readonly ILocalStorageService localStorageService;
        private readonly HttpClient httpClient;
        private readonly AuthenticationState askisuperadmin;

        public AuthStateProvider(ILocalStorageService LocalStorageService, HttpClient HttpClient)
        {
            localStorageService = LocalStorageService;
            httpClient = HttpClient;
            askisuperadmin = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        public async override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            try
            {
                bool IsTokenExist = await localStorageService.ContainKeyAsync(Constants.StorageVariables.Token);
                if (!IsTokenExist) return askisuperadmin;

                string Token = await localStorageService.GetItemAsStringAsync(Constants.StorageVariables.Token);

                if (String.IsNullOrEmpty(Token))
                    return askisuperadmin;

                string LoggedAccount = await localStorageService.GetItemAsStringAsync(Constants.StorageVariables.LoggedAccount);

                httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Token);

                var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, LoggedAccount) }, "jwtAuthType"));

                return new AuthenticationState(claimsPrincipal);
            }
            catch (Exception e) { askilogiclayer.Helpers.SecuriLogger.LogError("Auth Exception", e.Message); return askisuperadmin; }
        }

        public void TriggerWhenLogIn(string Account)
        {
            try
            {
                var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, Account) }, "jwtAuthType"));

                var state = Task.FromResult(new AuthenticationState(claimsPrincipal));

                NotifyAuthenticationStateChanged(state);
            }
            catch { }
        }

        public void TriggerWhenLogout()
        {
            try
            {
                var state = Task.FromResult(askisuperadmin);

                NotifyAuthenticationStateChanged(state);
            }
            catch { }
        }
    }
}
