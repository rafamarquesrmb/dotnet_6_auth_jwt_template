using AuthJwtDotnet.Model;
using System.Security.Claims;

namespace AuthJwtDotnet.Extensions
{
    public static class RoleClaimsExtension
    {
        public static IEnumerable<Claim> GetClaims(this User user)
        {
            var result = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };
            result.AddRange(
                user.Role.Select(role => new Claim(ClaimTypes.Role, user.Role))
                );
            return result;
        }
    }
}
