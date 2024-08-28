using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Ralph_Project.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace Ralph_Project.Data
{
    public class ApplicationDBContext : IdentityDbContext<IdentityUser>
    {
        public ApplicationDBContext(DbContextOptions<ApplicationDBContext> options) : base(options)
        {
        }

        public DbSet<Booking>? Bookings { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}
