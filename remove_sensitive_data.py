import re

def remove_name_and_address(text):
    text = re.sub(r"^(?:Patient|Name)\s*:\s*.+$", "", text, flags=re.IGNORECASE | re.MULTILINE)
    text = re.sub(r"^Address\s*:\s*.+$", "", text, flags=re.IGNORECASE | re.MULTILINE)
    text = "\n".join([line for line in text.splitlines() if line.strip() != ""])
    return text

def anonymize_phone(text):
    pattern = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    return re.sub(pattern, "phone", text)

def anonymize_email(text):
    pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    return re.sub(pattern, "email", text)

def anonymize_dates(text):
    pattern = (
        r"\b\d{1,2}/\d{1,2}/\d{4}\b"
        r"|\b\d{4}-\d{2}-\d{2}\b"
        r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,2},\s\d{4}\b"
    )
    matches = re.findall(pattern, text)
    replaced = 0
    for m in matches:
        if replaced == 0:
            text = text.replace(m, "dob", 1)
        elif replaced == 1:
            text = text.replace(m, "date_of_visit", 1)
        else:
            text = text.replace(m, "date", 1)
        replaced += 1
    return text

def anonymize_medical_number(text):
    return re.sub(r"\b\d{7}\b", "medical number", text)

def anonymize_all(text):
    text = remove_name_and_address(text)
    text = anonymize_phone(text)
    text = anonymize_email(text)
    text = anonymize_dates(text)
    text = anonymize_medical_number(text)
    return text

def main():
    file_path = input("Enter path to the text file: ").strip()
    with open(file_path, "r", encoding="utf-8") as f:
        data = f.read()
    cleaned = anonymize_all(data)
    print("\n--- Cleaned Data ---")
    print(cleaned)

if __name__ == "__main__":
    main()
