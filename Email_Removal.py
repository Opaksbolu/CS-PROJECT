
import re

def remove_email(text):
    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    return re.sub(email_pattern, "[email redacted]", text)

