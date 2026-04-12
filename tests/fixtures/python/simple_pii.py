import logging

logger = logging.getLogger(__name__)


class UserProfile:
    def __init__(self, email, full_name, phone_number, date_of_birth):
        self.email = email
        self.full_name = full_name
        self.phone_number = phone_number
        self.date_of_birth = date_of_birth


def process_user(user):
    # PII leaked to logs
    logging.info(f"Processing user: {user.email}")
    print(f"User phone: {user.phone_number}")

    # PII sent to external API
    requests.post("https://api.example.com/users", json={
        "email": user.email,
        "name": user.full_name,
    })

    # PII stored in DB
    cursor.execute(
        "INSERT INTO users (email, ssn) VALUES (%s, %s)",
        (user.email, user.ssn)
    )


password = input("Enter password: ")
api_key = os.environ.get("API_KEY")
ip_address = request.remote_addr
