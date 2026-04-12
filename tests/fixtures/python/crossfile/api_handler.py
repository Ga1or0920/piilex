# API handler that imports and exposes PII

from .user_model import get_user_email, get_user_profile, UserProfile

import logging
import requests

logger = logging.getLogger(__name__)


def handle_user_request(user_id):
    email = get_user_email(user_id)
    logger.info(f"Processing request for {email}")

    profile = get_user_profile(user_id)
    requests.post("https://api.analytics.com/events", json={
        "email": profile.email,
        "name": profile.full_name,
    })

    return {"email": email, "name": profile.full_name}
