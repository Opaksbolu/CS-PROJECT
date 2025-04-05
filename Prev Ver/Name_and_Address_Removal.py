import re

def extract_name_and_address(text):
    """
    Extracts the name and address from the text.
    
    The function searches for lines beginning with "Patient:" or "Name:" for the name,
    and for "Address:" for the address.
    
    Parameters:
        text (str): The input text.
        
    Returns:
        tuple: A tuple (name, address) if found, else (None, None).
    """
    # Extract name (matching "Patient:" or "Name:")
    name_match = re.search(r"(?:Patient|Name)\s*:\s*(.+)", text, re.IGNORECASE)
    name = name_match.group(1).strip() if name_match else None

    # Extract address (matching "Address:")
    address_match = re.search(r"Address\s*:\s*(.+)", text, re.IGNORECASE)
    address = address_match.group(1).strip() if address_match else None

    return name, address

def anonymize_text(text, name, address):
    """
    Replaces the extracted name and address in the text with placeholders 
    and anonymizes any occurrences of the extracted name.
    
    Parameters:
        text (str): The input text.
        name (str): The extracted name to replace.
        address (str): The extracted address to replace.
        
    Returns:
        str: The text with name and address anonymized.
    """
    # Replace the name and address lines with placeholders
    text = re.sub(r"^(?:Patient|Name)\s*:\s*.+$", "Name: [REDACTED]", text, flags=re.IGNORECASE | re.MULTILINE)
    text = re.sub(r"^Address\s*:\s*.+$", "Address: [REDACTED]", text, flags=re.IGNORECASE | re.MULTILINE)

    # Anonymize occurrences of the extracted name in the text (if found)
    if name:
        first_name = name.split()[0]  # Extract first name
        last_name = name.split()[-1]  # Extract last name
        name_variants = [re.escape(name), re.escape(first_name), re.escape(last_name), rf"Mr\.?\s*{re.escape(last_name)}"]

        # Create a regex pattern that matches any variant of the name
        name_pattern = r"\b(" + "|".join(name_variants) + r")\b"

        # Replace all occurrences with "[REDACTED]"
        text = re.sub(name_pattern, "[REDACTED]", text, flags=re.IGNORECASE)

    return text

def main():
    print("Please paste your document text. Enter a blank line to finish:")
    
    # Read multi-line input until a blank line is entered.
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    text = "\n".join(lines)
    
    # Display the original text
    print("\n--- Original Text ---")
    print(text)
    
    # Extract name and address from the provided text
    name, address = extract_name_and_address(text)
    
    print("\n--- Extracted Information ---")
    if name:
        print("Name:", name)
    else:
        print("Name not found in the document.")
    
    if address:
        print("Address:", address)
    else:
        print("Address not found in the document.")
    
    # Replace name and address with placeholders and anonymize name occurrences
    modified_text = anonymize_text(text, name, address)
    
    print("\n--- Modified Text (Name and Address Anonymized) ---")
    print(modified_text)

if __name__ == "__main__":
    main()
