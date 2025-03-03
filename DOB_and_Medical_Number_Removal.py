import re
def anonymize_dob(text):
    dob_pattern = r"\b\d{1,2}/\d{1,2}/\d{4}\b|\b\d{4}-\d{2}-\d{2}\b|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,2},\s\d{4}\b"
    dob_matches = re.findall(dob_pattern, text)

# Remove only the first date occurrence (DOB)
    if dob_matches:
        text = text.replace(dob_matches[0], "dob", 1)
    return text

def anonymize_medical_number(text):
    medical_number_pattern = r"\b\d{7}\b"
    text = re.sub(medical_number_pattern, "medical number", text)
    return text