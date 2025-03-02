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

def remove_extracted_lines(text):
    """
    Removes lines that contain the extracted name or address information.
    
    This function removes any line that starts with "Patient:" or "Name:" 
    and any line that starts with "Address:".
    
    Parameters:
        text (str): The input text.
        
    Returns:
        str: The text with the specified lines removed.
    """
    # Remove lines starting with "Patient:" or "Name:"
    text_without_name = re.sub(r"^(?:Patient|Name)\s*:\s*.+$", "", text, flags=re.IGNORECASE | re.MULTILINE)
    # Remove lines starting with "Address:"
    text_cleaned = re.sub(r"^Address\s*:\s*.+$", "", text_without_name, flags=re.IGNORECASE | re.MULTILINE)
    
    # Optionally, remove extra blank lines that might have been created
    text_cleaned = "\n".join([line for line in text_cleaned.splitlines() if line.strip() != ""])
    return text_cleaned

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
    
    # Remove the lines containing name and address from the text
    modified_text = remove_extracted_lines(text)
    
    print("\n--- Modified Text (Name and Address lines removed) ---")
    print(modified_text)

if __name__ == "__main__":
    main()
