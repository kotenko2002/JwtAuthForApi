using JwsAuthForApi.Data;
using Microsoft.EntityFrameworkCore;

namespace JwsAuthForApi.Repositories
{
    public class AuthApiContext : DbContext
    {
        public AuthApiContext(DbContextOptions<AuthApiContext> opt) : base(opt)
        {
            
        }

        public DbSet<User> Users { get; set; }
    }
}
