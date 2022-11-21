using System.ComponentModel.DataAnnotations;

namespace JwsAuthForApi.Dto
{
    public class UserDto
    {
        [MinLength(5)]
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
