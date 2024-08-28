document.addEventListener("DOMContentLoaded", async () => {
    const form = document.getElementById('editBookingForm');
    const errorElement = document.getElementById('error');
    const urlParams = new URLSearchParams(window.location.search);
    const bookingId = urlParams.get('id');

    if (!bookingId) {
        errorElement.textContent = 'Booking ID is missing.';
        return;
    }

    const dateFromInput = document.getElementById('dateFrom');
    const dateToInput = document.getElementById('dateTo');

    // Fetch booking details and populate the form
    try {
        const token = sessionStorage.getItem('authToken');
        if (!token) {
            throw new Error('You must be logged in to edit a booking.');
        }

        const response = await fetch(`https://localhost:7023/api/Booking/${bookingId}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error('Failed to retrieve booking details');
        }

        const booking = await response.json();
        document.getElementById('bookingId').value = booking.bookingId;
        document.getElementById('facilityDescription').value = booking.facilityDescription;
        dateFromInput.value = booking.bookingDateFrom;
        dateToInput.value = booking.bookingDateTo;

        // Set initial min/max values based on the loaded booking data
        dateFromInput.setAttribute('max', booking.bookingDateTo);
        dateToInput.setAttribute('min', booking.bookingDateFrom);

        // Set the booking ID in the transfer confirmation text
        document.getElementById('bookingIdText').textContent = booking.bookingId;

    } catch (error) {
        errorElement.textContent = error.message;
    }

    // Update the min/max attributes dynamically
    dateFromInput.addEventListener('change', () => {
        dateToInput.setAttribute('min', dateFromInput.value);
    });

    dateToInput.addEventListener('change', () => {
        dateFromInput.setAttribute('max', dateToInput.value);
    });

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const facilityDescription = document.getElementById('facilityDescription').value;
        const dateFrom = dateFromInput.value;
        const dateTo = dateToInput.value;

        if (!facilityDescription || !dateFrom || !dateTo) {
            errorElement.textContent = 'All fields are required.';
            return;
        }

        try {
            const token = sessionStorage.getItem('authToken');
            if (!token) {
                throw new Error('You must be logged in to update a booking.');
            }

            const response = await fetch(`https://localhost:7023/api/Booking/${bookingId}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    facilityDescription,
                    bookingDateFrom: dateFrom,
                    bookingDateTo: dateTo,
                    bookedBy: '', // Placeholder, will be handled by the API
                    bookingStatus: 'placeholder' // Placeholder, will be handled by the API
                })
            });

            if (!response.ok) {
                throw new Error('Failed to update booking');
            }

            alert('Booking updated successfully!');
            window.location.href = 'bookings.html';

        } catch (error) {
            errorElement.textContent = error.message;
        }
    });

    // Modal and Transfer Booking logic
    const modal = document.getElementById('transferBookingModal');
    const btn = document.getElementById('transferBookingBtn');
    const span = document.getElementsByClassName('close')[0];
    const confirmInput = document.getElementById('confirmTransfer');
    const transferButton = document.getElementById('confirmTransferBtn');

    // When the user clicks the button, open the modal
    btn.onclick = () => {
        modal.style.display = "block";
    }

    // When the user clicks on (x), close the modal
    span.onclick = () => {
        modal.style.display = "none";
    }

    // When the user clicks anywhere outside of the modal, close it
    window.onclick = (event) => {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }

    // Enable/disable transfer button based on confirmation input
    confirmInput.addEventListener('input', () => {
        const expectedText = `Transfer booking id ${bookingId}`;
        if (confirmInput.value === expectedText) {
            transferButton.classList.add('enabled');
            transferButton.disabled = false;
        } else {
            transferButton.classList.remove('enabled');
            transferButton.disabled = true;
        }
    });

    // Handle the transfer booking functionality
    transferButton.addEventListener('click', async () => {
        const newBookedBy = document.getElementById('transferToUser').value;

        if (!newBookedBy) {
            errorElement.textContent = 'Please enter a username to transfer the booking to.';
            return;
        }

        try {
            const token = sessionStorage.getItem('authToken');
            if (!token) {
                throw new Error('You must be logged in to transfer a booking.');
            }

            const response = await fetch(`https://localhost:7023/api/Booking/update-booked-by/${bookingId}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(newBookedBy)
            });

            if (!response.ok) {
                const errorMessage = await response.text();
                throw new Error(errorMessage || 'Failed to transfer booking');
            }

            alert('Booking transferred successfully!');
            window.location.href = 'bookings.html'; // Redirect to bookings.html

        } catch (error) {
            errorElement.textContent = error.message;
        }
    });
});
