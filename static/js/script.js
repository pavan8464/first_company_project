// Handle alert form submission on the bulk results page
document.addEventListener('DOMContentLoaded', () => {
    const alertForm = document.getElementById('alert-form');

    if (alertForm) {
        alertForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            const recipients = document.getElementById('recipients').value;
            const message = document.getElementById('alert-message').value;

            if (!recipients || !message) {
                alert("Please fill in all fields.");
                return;
            }

            const response = await fetch('/send_alert', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipients, message })
            });

            const result = await response.json();
            if (result.status === 'success') {
                alert('Alerts sent successfully!');
            } else {
                alert('Failed to send alerts. Please try again.');
            }
        });
    }
});
