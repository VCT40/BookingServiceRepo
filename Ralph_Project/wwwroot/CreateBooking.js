document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById('createBookingForm');
    const errorElement = document.getElementById('error');

    // Set minimum dates for the date inputs
    const today = new Date().toISOString().split('T')[0];
    const tomorrow = new Date(new Date().setDate(new Date().getDate() + 1)).toISOString().split('T')[0];

    document.getElementById('dateFrom').setAttribute('min', today);
    document.getElementById('dateTo').setAttribute('min', tomorrow);

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const facilityDescription = document.getElementById('facilityDescription').value;
        const dateFrom = document.getElementById('dateFrom').value;
        const dateTo = document.getElementById('dateTo').value;

        if (!facilityDescription || !dateFrom || !dateTo) {
            errorElement.textContent = 'All fields are required.';  
            return;
        }

        try {
            const token = sessionStorage.getItem('authToken');
            if (!token) {
                throw new Error('You must be logged in to create a booking.');
            }

            const response = await fetch('https://localhost:7023/api/Booking', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    facilityDescription,
                    bookingDateFrom: dateFrom, // Send as string
                    bookingDateTo: dateTo,     // Send as string
                    bookedBy: '',              // Placeholder, will be set by the API
                    bookingStatus: 'placeholder'          // Placeholder, will be set by the API
                })
            });

            if (!response.ok) {
                throw new Error('Failed to create booking');
            }

            const result = await response.json();
            alert('Booking created successfully!');
            form.reset();

        } catch (error) {
            errorElement.textContent = error.message;
        }
    });
});
