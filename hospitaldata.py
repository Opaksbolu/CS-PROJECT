import re
import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# ================================
# Begin Data_Anonymizer_GUI.py code
# ================================

def extract_name_and_address(text):
    name_match = re.search(r"(?:Patient|Name)\s*:\s*(.+)", text, re.IGNORECASE)
    name = name_match.group(1).strip() if name_match else None

    address_match = re.search(r"Address\s*:\s*(.+)", text, re.IGNORECASE)
    address = address_match.group(1).strip() if address_match else None

    return name, address

def remove_extracted_lines(text):
    text_without_name = re.sub(
        r"^(?:Patient|Name)\s*:\s*.+$",
        "",
        text,
        flags=re.IGNORECASE | re.MULTILINE
    )
    text_cleaned = re.sub(
        r"^Address\s*:\s*.+$",
        "",
        text_without_name,
        flags=re.IGNORECASE | re.MULTILINE
    )
    # Remove extra blank lines
    text_cleaned = "\n".join([line for line in text_cleaned.splitlines() if line.strip() != ""])
    return text_cleaned

def anonymize_dob(text):
    dob_pattern = (
        r"\b\d{1,2}/\d{1,2}/\d{4}\b"
        r"|\b\d{4}-\d{2}-\d{2}\b"
        r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,2},\s\d{4}\b"
    )
    dob_matches = re.findall(dob_pattern, text)
    if dob_matches:
        # Replace only the first date found with "dob"
        text = text.replace(dob_matches[0], "dob", 1)
    return text

def anonymize_medical_number(text):
    return re.sub(r"\b\d{7}\b", "medical number", text)

def anonymize_phone(text):
    """
    Simple phone pattern for typical US phone numbers like 123-456-7890,
    (123) 456-7890, 123.456.7890, etc.
    """
    pattern = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    return re.sub(pattern, "phone", text)

def anonymize_email(text):
    pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    return re.sub(pattern, "email", text)

def process_single_record(record):
    """
    Process one 'database entry' or 'record':
      - Extract name, address
      - Remove name/address lines
      - Anonymize DOB, medical number, phone, email
    Returns (extracted_name, extracted_address, anonymized_text).
    """
    name, address = extract_name_and_address(record)
    cleaned = remove_extracted_lines(record)
    cleaned = anonymize_dob(cleaned)
    cleaned = anonymize_medical_number(cleaned)
    cleaned = anonymize_phone(cleaned)
    cleaned = anonymize_email(cleaned)
    return name, address, cleaned

def process_all_records(full_text):
    """
    Splits the text on each 'Patient:' line (ignoring case).
    This ensures that everything for ONE patient stays together.
    If there's only one 'Patient:' line, you'll only get one record.
    """
    chunks = re.split(r"(?i)(?=Patient\s*:\s*)", full_text.strip())
    if len(chunks) == 1:
        return [process_single_record(chunks[0])]
    results = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        name, address, anon_text = process_single_record(chunk)
        results.append((name, address, anon_text))
    return results

def upload_file():
    file_path = filedialog.askopenfilename(
        title="Select a Text File",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                file_content = f.read()
            text_input.delete("1.0", tk.END)
            text_input.insert(tk.END, file_content)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file: {e}")

def process_gui():
    full_text = text_input.get("1.0", tk.END).strip()
    if not full_text:
        messagebox.showerror("Error", "No text provided!")
        return

    all_results = process_all_records(full_text)

    output_window = tk.Toplevel(root)
    output_window.title("Anonymized Output")
    canvas = tk.Canvas(output_window)
    scrollbar = tk.Scrollbar(output_window, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    container_frame = tk.Frame(canvas)
    canvas.create_window((0, 0), window=container_frame, anchor="nw")

    def on_frame_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))
    container_frame.bind("<Configure>", on_frame_configure)

    for i, (name, address, anon_text) in enumerate(all_results, start=1):
        record_frame = tk.LabelFrame(container_frame, text=f"Record {i}", padx=10, pady=10)
        record_frame.pack(fill="x", expand=True, padx=5, pady=5)
        info_text = (
            f"Extracted Information:\n"
            f"Name: {name if name else 'Not Found'}\n"
            f"Address: {address if address else 'Not Found'}\n\n"
            f"Modified Text (Sensitive Data Removed):\n"
        )
        info_label = tk.Label(record_frame, text=info_text, justify=tk.LEFT)
        info_label.pack(anchor="w")
        text_box = scrolledtext.ScrolledText(record_frame, wrap=tk.WORD, width=60, height=10)
        text_box.insert(tk.END, anon_text)
        text_box.config(state=tk.DISABLED)
        text_box.pack()

def run_Data_Anonymizer_GUI():
    global root, text_input
    root = tk.Tk()
    root.title("Data Anonymizer (Multiple Records)")
    frame = tk.Frame(root)
    frame.pack(padx=10, pady=10)
    global text_input
    text_input = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=60, height=15)
    text_input.pack()
    upload_button = tk.Button(frame, text="Upload Text File", command=upload_file)
    upload_button.pack(pady=5)
    process_button = tk.Button(frame, text="Process Text", command=process_gui)
    process_button.pack(pady=5)
    
    # Bind the window close event to save content to __pycache__ and exit
    def on_close():
        content = text_input.get("1.0", tk.END).strip()
        if content:
            cache_folder = "__pycache__"
            if not os.path.exists(cache_folder):
                os.mkdir(cache_folder)
            output_path = os.path.join(cache_folder, "uploaded.txt")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Content saved to {output_path}")
        root.destroy()
        sys.exit(0)
    
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

# ================================
# End Data_Anonymizer_GUI.py code
# ================================

# (The remaining parts of your code remain unchanged below but will not be executed.)

def anonymize_dob_DOBRemoval(text):
    dob_pattern = r"\b\d{1,2}/\d{1,2}/\d{4}\b|\b\d{4}-\d{2}-\d{2}\b|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,2},\s\d{4}\b"
    dob_matches = re.findall(dob_pattern, text)
    if dob_matches:
        text = text.replace(dob_matches[0], "dob", 1)
    return text

def anonymize_medical_number_DOBRemoval(text):
    medical_number_pattern = r"\b\d{7}\b"
    text = re.sub(medical_number_pattern, "medical number", text)
    return text

def remove_email(text):
    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    return re.sub(email_pattern, "email", text)

def anonymize_text_NameAddress(text, name, address):
    text = re.sub(r"^(?:Patient|Name)\s*:\s*.+$", "Name: [REDACTED]", text, flags=re.IGNORECASE | re.MULTILINE)
    text = re.sub(r"^Address\s*:\s*.+$", "Address: [REDACTED]", text, flags=re.IGNORECASE | re.MULTILINE)
    if name:
        first_name = name.split()[0]
        last_name = name.split()[-1]
        name_variants = [re.escape(name), re.escape(first_name), re.escape(last_name), rf"Mr\.?\s*{re.escape(last_name)}"]
        name_pattern = r"\b(" + "|".join(name_variants) + r")\b"
        text = re.sub(name_pattern, "[REDACTED]", text, flags=re.IGNORECASE)
    return text

def run_Name_and_Address_Removal():
    print("Please paste your document text. Enter a blank line to finish:")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    text = "\n".join(lines)
    print("\n--- Original Text ---")
    print(text)
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
    modified_text = anonymize_text_NameAddress(text, name, address)
    print("\n--- Modified Text (Name and Address Anonymized) ---")
    print(modified_text)

def read_file(input_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            return infile.read()
    except FileNotFoundError:
        print("Error: Input file not found. Check the file path.")
        return None
    except PermissionError:
        print("Error: Permission denied. Try running the script as an administrator.")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

def anonymize_phone_PhoneRemoval(content):
    pattern = re.compile(r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
    return pattern.sub("*phone*", content)

def anonymize_name_PhoneRemoval(content):
    return content

def anonymize_address_PhoneRemoval(content):
    return content

def anonymize_dob_PhoneRemoval(content):
    return content

def anonymize_ssn_PhoneRemoval(content):
    return content

def anonymize_email_PhoneRemoval(content):
    return content

def run_Phone_Number_Removal():
    input_file = r"C:\Users\llama\OneDrive\Desktop\input.txt"
    output_file = r"C:\Users\llama\OneDrive\Desktop\output.txt"
    content = read_file(input_file)
    if content is not None:
        content = anonymize_phone_PhoneRemoval(content)
        content = anonymize_name_PhoneRemoval(content)
        content = anonymize_address_PhoneRemoval(content)
        content = anonymize_dob_PhoneRemoval(content)
        content = anonymize_ssn_PhoneRemoval(content)
        content = anonymize_email_PhoneRemoval(content)
        try:
            with open(output_file, 'w', encoding='utf-8') as outfile:
                outfile.write(content)
            print("Anonymization complete. Output saved to:", output_file)
        except Exception as e:
            print(f"Error writing output file: {e}")

def remove_name_and_address(text):
    text = re.sub(r"^(?:Patient|Name)\s*:\s*.+$", "", text, flags=re.IGNORECASE | re.MULTILINE)
    text = re.sub(r"^Address\s*:\s*.+$", "", text, flags=re.IGNORECASE | re.MULTILINE)
    text = "\n".join([line for line in text.splitlines() if line.strip() != ""])
    return text

def anonymize_phone_all(text):
    pattern = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    return re.sub(pattern, "phone", text)

def anonymize_email_all(text):
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

def anonymize_medical_number_all(text):
    return re.sub(r"\b\d{7}\b", "medical number", text)

def anonymize_all(text):
    text = remove_name_and_address(text)
    text = anonymize_phone_all(text)
    text = anonymize_email_all(text)
    text = anonymize_dates(text)
    text = anonymize_medical_number_all(text)
    return text

def run_remove_sensitive_data():
    file_path = input("Enter path to the text file: ").strip()
    with open(file_path, "r", encoding="utf-8") as f:
        data = f.read()
    cleaned = anonymize_all(data)
    print("\n--- Cleaned Data ---")
    print(cleaned)

if __name__ == "__main__":
    # Run the GUI part (this will block until you close the window)
    run_Data_Anonymizer_GUI()
    
    # After the GUI closes, the on_close function will save the text to __pycache__/uploaded.txt and call sys.exit(0)
    # Therefore, none of the interactive console parts below will run.
    #
    # If you want to run them as well, remove the sys.exit(0) call in the on_close function.
    
    # Run the Name and Address Removal interactive console part
    run_Name_and_Address_Removal()
    
    # Run the Phone Number Removal part (uses hardcoded file paths)
    run_Phone_Number_Removal()
    
    # Run the Remove Sensitive Data interactive part
    run_remove_sensitive_data()






