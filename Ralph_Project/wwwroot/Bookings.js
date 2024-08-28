document.addEventListener("DOMContentLoaded", () => {
    const bookingsTable = document.getElementById('bookingsTable').querySelector('tbody');
    const errorElement = document.getElementById('error');
    const logoutButton = document.getElementById('logoutButton');
    const logoutModal = document.getElementById('logoutModal');
    const confirmLogout = document.getElementById('confirmLogout');
    const cancelLogout = document.getElementById('cancelLogout');

    const deleteModal = document.getElementById('deleteModal');
    const deleteMessage = document.getElementById('deleteMessage');
    const deleteInput = document.getElementById('deleteInput');
    const confirmDelete = document.getElementById('confirmDelete');
    const cancelDelete = document.getElementById('cancelDelete');

    let currentBookingId = null;

    async function fetchBookings() {
        try {
            const token = sessionStorage.getItem('authToken');

            if (!token) {
                throw new Error('You must be logged in to view bookings.');
            }

            const response = await fetch('https://localhost:7023/api/Booking', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to retrieve bookings');
            }

            const bookings = await response.json();

            bookings.forEach(booking => {
                const row = document.createElement('tr');

                row.innerHTML = `
                    <td>${booking.bookingId}</td>
                    <td>${booking.facilityDescription}</td>
                    <td>${booking.bookingDateFrom}</td>
                    <td>${booking.bookingDateTo}</td>
                    <td>${booking.bookingStatus}</td>
                    <td>${booking.bookedBy}</td>
                    <td><a href="EditBooking.html?id=${booking.bookingId}"><button class="edit-button">✏️</button></a></td>
                    <td><button class="delete-button" style="color: red;" data-booking-id="${booking.bookingId}">🗑️</button></td>
                `;

                bookingsTable.appendChild(row);
            });

            // Add event listeners for delete buttons
            document.querySelectorAll('.delete-button').forEach(button => {
                button.addEventListener('click', handleDeleteClick);
            });

        } catch (error) {
            errorElement.textContent = error.message;
        }
    }

    async function updateStatuses() {
        try {
            const token = sessionStorage.getItem('authToken');

            const response = await fetch('https://localhost:7023/api/Booking/update-statuses', {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to update statuses');
            }

            // After updating statuses, fetch bookings again to reflect changes
            bookingsTable.innerHTML = '';
            fetchBookings();

        } catch (error) {
            errorElement.textContent = error.message;
        }
    }

    function handleDeleteClick(event) {
        currentBookingId = event.target.getAttribute('data-booking-id');
        deleteMessage.textContent = `To confirm, type "Delete booking id ${currentBookingId}" in the box below`;
        deleteInput.value = '';
        confirmDelete.classList.remove('enabled');
        confirmDelete.disabled = true;
        deleteModal.style.display = 'flex';
    }

    deleteInput.addEventListener('input', () => {
        const expectedText = `Delete booking id ${currentBookingId}`;
        if (deleteInput.value === expectedText) {
            confirmDelete.classList.add('enabled');
            confirmDelete.disabled = false;
        } else {
            confirmDelete.classList.remove('enabled');
            confirmDelete.disabled = true;
        }
    });

    confirmDelete.addEventListener('click', () => {
        deleteModal.style.display = 'none';
        deleteBooking(currentBookingId);
    });

    cancelDelete.addEventListener('click', () => {
        deleteModal.style.display = 'none';
    });

    async function deleteBooking(bookingId) {
        try {
            const token = sessionStorage.getItem('authToken');

            const response = await fetch(`https://localhost:7023/api/Booking/${bookingId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error('Failed to delete booking');
            }

            // Reload bookings after deletion
            bookingsTable.innerHTML = '';
            fetchBookings();

        } catch (error) {
            errorElement.textContent = error.message;
        }
    }

    function showLogoutModal() {
        logoutModal.style.display = 'flex';
    }

    function hideLogoutModal() {
        logoutModal.style.display = 'none';
    }

    function logout() {
        sessionStorage.removeItem('authToken');
        window.location.href = 'login.html';
    }

    logoutButton.addEventListener('click', showLogoutModal);
    confirmLogout.addEventListener('click', () => {
        hideLogoutModal();
        logout();
    });
    cancelLogout.addEventListener('click', hideLogoutModal);

    // Update statuses and then fetch bookings
    updateStatuses();
});
