# User model with PII fields

class UserProfile:
    def __init__(self, email, full_name, phone_number, ssn):
        self.email = email
        self.full_name = full_name
        self.phone_number = phone_number
        self.ssn = ssn


def get_user_email(user_id):
    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()[0]


def get_user_profile(user_id):
    return UserProfile(
        email="test@example.com",
        full_name="John Doe",
        phone_number="+1234567890",
        ssn="123-45-6789",
    )
