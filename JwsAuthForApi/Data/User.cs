using System.ComponentModel.DataAnnotations;

namespace JwsAuthForApi.Data
{
    public class User
    {
        public int Id { get; set; }
        [Required]
        [MinLength(5)]
        public string Username { get; set; }
        [Required]
        public string PasswordHash { get; set; }
        [Required]
        public string PasswordSalt { get; set; }
    }
}
