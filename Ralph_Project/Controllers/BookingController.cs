using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Ralph_Project.Data;
using Ralph_Project.Models;
using Ralph_Project.Modles;
using System.Security.Claims;

namespace Ralph_Project.Controllers
{
    // Require authorization for all actions in this controller
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class BookingController : ControllerBase
    {
        // Inject the application database context
        private readonly ApplicationDBContext _context;
        public BookingController(ApplicationDBContext context)
        {
            _context = context;
        }

        // Retrieve all bookings; admins can see all, regular users can only see their own
        [HttpGet]
        public IActionResult GetAll()
        {
            var username = User.Identity.Name;

            if (User.IsInRole(UserRoles.Admin))
            {
                // Admins can see all bookings
                return Ok(_context.Bookings.ToList());
            }
            else
            {
                // Users can only see their own bookings
                var userBookings = _context.Bookings
                    .Where(b => b.BookedBy == username)
                    .ToList();

                return Ok(userBookings);
            }
        }

        // Retrieve a specific booking by its ID
        [HttpGet("{id}")]
        public IActionResult GetBookingById(int id)
        {
            var username = User.Identity.Name;

            var booking = _context.Bookings.FirstOrDefault(b => b.BookingId == id);
            if (booking == null)
                return NotFound($"Booking with id {id} not found.");

            if (User.IsInRole(UserRoles.Admin))
            {
                // Admins can access any booking
                return Ok(booking);
            }
            else
            {
                // Users can only access their own bookings
                if (booking.BookedBy != username)
                    return Unauthorized("You do not have permission to access this booking.");

                return Ok(booking);
            }
        }

        // Create a new booking
        [HttpPost]
        public IActionResult CreateBooking([FromBody] Booking booking)
        {
            if (booking == null)
                return BadRequest("Invalid booking data.");

            // Assign the current user's username to the booking
            var username = User.Identity.Name;
            booking.BookedBy = username;

            // Convert string dates to DateTime objects
            DateTime bookingDateFrom;
            DateTime bookingDateTo;

            if (!DateTime.TryParseExact(booking.BookingDateFrom, "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None, out bookingDateFrom) ||
                !DateTime.TryParseExact(booking.BookingDateTo, "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.None, out bookingDateTo))
            {
                return BadRequest("Invalid date format.");
            }

            // Determine the booking status based on the current date and the booking dates
            var currentDate = DateTime.UtcNow.Date; // Use UTC and only the date part for comparison
            if (currentDate < bookingDateFrom)
            {
                booking.BookingStatus = "Pending";
            }
            else if (currentDate >= bookingDateFrom && currentDate <= bookingDateTo)
            {
                booking.BookingStatus = "Ongoing";
            }
            else
            {
                booking.BookingStatus = "Completed";
            }

            // Save the new booking to the database
            _context.Bookings.Add(booking);
            _context.SaveChanges();

            return Ok(booking);
        }

        // Update an existing booking
        [HttpPut("{id}")]
        public IActionResult UpdateBooking(int id, [FromBody] Booking updatedBooking)
        {
            if (updatedBooking == null)
                return BadRequest("Invalid booking data.");

            var existingBooking = _context.Bookings.FirstOrDefault(b => b.BookingId == id);
            if (existingBooking == null)
                return NotFound($"Booking with id {id} is not found.");

            // Preserve the existing BookedBy value
            updatedBooking.BookedBy = existingBooking.BookedBy;

            // Update the fields of the existing booking with the new values
            existingBooking.FacilityDescription = updatedBooking.FacilityDescription;
            existingBooking.BookingDateFrom = updatedBooking.BookingDateFrom;
            existingBooking.BookingDateTo = updatedBooking.BookingDateTo;
            existingBooking.BookingStatus = updatedBooking.BookingStatus;
            existingBooking.BookedBy = updatedBooking.BookedBy; // Ensure the existing value is retained

            // Save the updated booking to the database
            _context.Bookings.Update(existingBooking);
            _context.SaveChanges();

            return Ok(existingBooking);
        }

        // Update the 'BookedBy' field of a booking
        [HttpPut("update-booked-by/{id}")]
        public IActionResult UpdateBookedBy(int id, [FromBody] string newBookedBy)
        {
            if (string.IsNullOrEmpty(newBookedBy))
                return BadRequest("New BookedBy username must be provided.");

            var existingBooking = _context.Bookings.FirstOrDefault(b => b.BookingId == id);
            if (existingBooking == null)
                return NotFound($"Booking with id {id} not found.");

            // Ensure that the current user is authorized to update the booking
            if (!IsUserAuthorizedToUpdateBooking(existingBooking))
                return NotFound($"Booking with id {id} not found.");

            // If the current user is not an admin
            if (User.IsInRole(UserRoles.User))
            {
                // Prevent transferring the booking to the same user or an admin
                if (existingBooking.BookedBy == newBookedBy)
                    return BadRequest("You cannot transfer the booking to your own account.");

                if (IsAdminUser(newBookedBy))
                    return Unauthorized("You are not authorized to transfer bookings to an admin account.");
            }

            // Ensure the new 'BookedBy' user exists
            if (!DoesUserExist(newBookedBy))
                return BadRequest($"User {newBookedBy} does not exist.");

            // Update and save changes
            existingBooking.BookedBy = newBookedBy;
            _context.Bookings.Update(existingBooking);
            _context.SaveChanges();

            return Ok(existingBooking);
        }

        // Helper methods for checking user roles and permissions

        private bool IsUserAuthorizedToUpdateBooking(Booking existingBooking)
        {
            // Check if the user is an admin or the one who made the booking
            return User.IsInRole(UserRoles.Admin) || existingBooking.BookedBy == User.Identity.Name;
        }

        private bool IsAdminUser(string username)
        {
            // Check if the user is an admin
            return _context.Users
                .Join(_context.UserRoles, u => u.Id, ur => ur.UserId, (u, ur) => new { u.UserName, ur.RoleId })
                .Join(_context.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => new { ur.UserName, r.Name })
                .Any(u => u.UserName == username && u.Name == UserRoles.Admin);
        }

        private bool DoesUserExist(string username)
        {
            // Check if the user exists in the database
            return _context.Users.Any(u => u.UserName == username);
        }

        // Delete a booking
        [HttpDelete("{id}")]
        public IActionResult DeleteBooking(int id)
        {
            // Find the booking by ID
            var booking = _context.Bookings.FirstOrDefault(b => b.BookingId == id);
            if (booking == null || (User.IsInRole(UserRoles.User) && booking.BookedBy != User.Identity.Name))
            {
                // If the booking doesn't exist or the user is trying to delete a booking not under their name
                return NotFound("This booking doesn't exist.");
            }

            // Remove the booking and save changes
            _context.Bookings.Remove(booking);
            _context.SaveChanges();

            return Ok("Booking deleted successfully.");
        }

        // Update the statuses of all bookings based on the current date
        [HttpPut("update-statuses")]
        public IActionResult UpdateStatuses()
        {
            // Get all bookings
            var bookings = _context.Bookings.ToList();
            var today = DateTime.UtcNow.ToString("yyyy-MM-dd"); // Assuming UTC, adjust if needed

            // Update each booking's status based on the current date
            foreach (var booking in bookings)
            {
                if (string.Compare(today, booking.BookingDateTo) > 0)
                {
                    booking.BookingStatus = "completed";
                }
                else if (string.Compare(today, booking.BookingDateFrom) > 0)
                {
                    booking.BookingStatus = "ongoing";
                }
                else
                {
                    booking.BookingStatus = "pending";
                }
            }

            // Save changes to the database
            _context.Bookings.UpdateRange(bookings);
            _context.SaveChanges();

            return Ok("Statuses updated.");
        }
    }
}
