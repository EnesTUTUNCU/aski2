using askiapp.Model;
using Blazored.LocalStorage;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using static askidatalayer.Models.Enums;

namespace askiapp.Helpers
{
    public static class WebAppHelper
    {
        public static string ParseToken(string Token, string Key)
        {
            try
            {
                if (String.IsNullOrEmpty(Token)) return String.Empty;
                //
                var handler = new JwtSecurityTokenHandler();
                var decodedValue = handler.ReadJwtToken(Token);
                var value = decodedValue.Claims.First(claim => claim.Type == Key).Value;
                //
                return value;
            }
            catch { }
            return String.Empty;
        }

        public static bool IsUserAskiAdmin(int Role)
        {
            try
            {
                return Role == (int)askidatalayer.Models.Enums.UserAccessLevel.AskiSuperAdmin;
            }
            catch { }
            return false;
        }

        public static bool IsUserAskiOperation(int Role)
        {
            try
            {
                return Role == (int)askidatalayer.Models.Enums.UserAccessLevel.AskiOperation;
            }
            catch { }
            return false;
        }

        public static bool IsUserCompanyAdmin(int Role)
        {
            try
            {
                return Role == (int)askidatalayer.Models.Enums.UserAccessLevel.CustomerSuperAdmin;
            }
            catch { }
            return false;
        }

        public static bool IsUserCompanyOperation(int Role)
        {
            try
            {
                return Role == (int)askidatalayer.Models.Enums.UserAccessLevel.CustomerOperation;
            }
            catch { }
            return false;
        }

        public static bool IsUserAski(int Role)
        {
            try
            {
                return Role == (int)askidatalayer.Models.Enums.UserAccessLevel.AskiUser;
            }
            catch { }
            return false;
        }

        public static string UserRole(int Role)
        {
            try
            {
                if (Role == (int)askidatalayer.Models.Enums.UserAccessLevel.AskiUser)
                {
                    return "Bizdensin";
                }
                else if (Role == (int)askidatalayer.Models.Enums.UserAccessLevel.AskiSuperAdmin
                    || Role == (int)askidatalayer.Models.Enums.UserAccessLevel.CustomerSuperAdmin)
                {
                    return "Yönetici";
                }
                else if (Role == (int)askidatalayer.Models.Enums.UserAccessLevel.AskiOperation
                    || Role == (int)askidatalayer.Models.Enums.UserAccessLevel.CustomerOperation)
                {
                    return "Operasyon Görevlisi";
                }
                else
                {
                    return "Bilinmeyen Yetki";
                }
            }
            catch { }
            return "Bilinmeyen Yetki";
        }

        public static class Text
        {
            public static string UTF8(string val)
            {
                try
                {
                    byte[] bytes = Encoding.Default.GetBytes(val);
                    return Encoding.UTF8.GetString(bytes);
                }
                catch { return val; }
            }
            public static byte[] GetByte(string val)
            {
                try
                {
                    return Encoding.Default.GetBytes(val);
                }
                catch { return null; }
            }
        }

        public static string TokenGenerate(string username, string userrole, string secretKey, string ipaddress, string addressfamily, string agentname, string UserId, DateTime expiredOn)
        {
            try
            {
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[] {
                        new Claim(TokenHeaderVariables.Username, username),
                        new Claim(TokenHeaderVariables.Role, userrole),
                        new Claim(TokenHeaderVariables.IPAddress, ipaddress),
                        new Claim(TokenHeaderVariables.AddressFamily, addressfamily),
                        new Claim(TokenHeaderVariables.AgentName, agentname),
                        new Claim(TokenHeaderVariables.UserId, UserId),
                    }),
                    Expires = expiredOn,
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)), SecurityAlgorithms.HmacSha256Signature)
                };
                var tokenHandler = new JwtSecurityTokenHandler();
                var securityToken = tokenHandler.CreateToken(tokenDescriptor);
                var token = tokenHandler.WriteToken(securityToken);
                return token;
            }
            catch (Exception e)
            {
                return null;
            }
        }

        public static async Task<bool> IsTokenValid(ILocalStorageService _LocalStorageService)
        {
            try
            {
                string Token = await _LocalStorageService.GetItemAsStringAsync(Constants.StorageVariables.Token);

                var TokenDB = askidatalayer.Functions.System.IsThereToken(Token);

                return askidatalayer.Functions.System.IsTokenValid(TokenDB);

            }
            catch { return false; }
        }

    }
}
