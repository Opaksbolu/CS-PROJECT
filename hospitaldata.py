import re
import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
# Removed functools import as it's no longer needed for lambda with args

# ================================
# Begin Updated Data_Anonymizer_GUI.py code (Auto Save)
# ================================

# --- (Helper functions: extract_name_and_address, remove_extracted_lines,
# ---  anonymize_dob, anonymize_medical_number, anonymize_phone,
# ---  anonymize_email, process_single_record, process_all_records remain the same) ---

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
    # Split using a lookahead assertion to keep the 'Patient:' line with the chunk
    chunks = re.split(r"(?i)(?=^\s*Patient\s*:\s*)", full_text.strip(), flags=re.MULTILINE)
    if len(chunks) <= 1 and (not chunks or not re.match(r"(?i)^\s*Patient\s*:\s*", chunks[0])):
        # If no 'Patient:' line found, or input is empty, treat the whole text as one record
         if not full_text.strip():
              return [] # Return empty list if input is empty
         return [process_single_record(full_text.strip())] # Process the whole text
    results = []
    for chunk in chunks:
        if not chunk.strip(): # Skip empty chunks resulting from split
            continue
        # Ensure the chunk actually starts with Patient: before processing
        # This avoids processing potential empty strings from the split
        if re.match(r"(?i)^\s*Patient\s*:\s*", chunk):
             name, address, anon_text = process_single_record(chunk)
             results.append((name, address, anon_text))
        elif not results and chunk.strip(): # Handle text before the first 'Patient:' if any
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

# REMOVED save_record function - no longer needed

def process_gui():
    full_text = text_input.get("1.0", tk.END).strip()
    if not full_text:
        messagebox.showerror("Error", "No text provided!")
        return

    all_results = process_all_records(full_text)

    if not all_results:
         messagebox.showinfo("Info", "No records found or processed.")
         return # Exit if no results

    # --- Combine Anonymized Text for Auto-Saving ---
    combined_anonymized_text = []
    for i, (name, address, anon_text) in enumerate(all_results, start=1):
        # Add a header for clarity in the combined file
        record_header = f"--- Record {i} ---"
        if name:
            record_header += f" (Name: {name})" # Optionally add extracted name
        combined_anonymized_text.append(record_header)
        combined_anonymized_text.append(anon_text)
        combined_anonymized_text.append("\n") # Add space between records

    full_output_text = "\n".join(combined_anonymized_text)

    # --- Auto-Save the Combined Text ---
    try:
        cache_folder = "__pycache__"
        if not os.path.exists(cache_folder):
            os.makedirs(cache_folder) # Use makedirs to create parent dirs if needed
        # Let's name the output file clearly
        output_filename = "anonymized_records_output.txt"
        output_path = os.path.join(cache_folder, output_filename)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_output_text)

        # Inform user about auto-save
        messagebox.showinfo("Auto-Saved", f"Anonymized records automatically saved to:\n{output_path}")

    except Exception as e:
        messagebox.showerror("Auto-Save Error", f"Could not automatically save results:\n{e}")
        # Continue to show the results window even if saving failed

    # --- Create Output Window for Viewing (No Save Buttons) ---
    output_window = tk.Toplevel(root)
    output_window.title("Anonymized Output (View Only)")

    # --- Create Scrollable Area ---
    canvas = tk.Canvas(output_window)
    scrollbar = tk.Scrollbar(output_window, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas) # Frame that holds the content

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")
        )
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # --- Display Each Record for Viewing ---
    for i, (name, address, anon_text) in enumerate(all_results, start=1):
        record_frame = tk.LabelFrame(scrollable_frame, text=f"Record {i}", padx=10, pady=10)
        record_frame.pack(fill="x", expand=True, padx=5, pady=5, anchor="nw") # Anchor NW

        info_text = (
            f"Extracted Information:\n"
            f"  Name: {name if name else 'Not Found'}\n"
            f"  Address: {address if address else 'Not Found'}\n\n"
            f"Anonymized Text:"
        )
        info_label = tk.Label(record_frame, text=info_text, justify=tk.LEFT)
        info_label.pack(anchor="w", pady=(0, 5)) # Add padding below

        text_box = scrolledtext.ScrolledText(record_frame, wrap=tk.WORD, width=70, height=10)
        text_box.insert(tk.END, anon_text)
        text_box.config(state=tk.DISABLED) # Keep it read-only
        text_box.pack(fill="x", expand=True, pady=(0, 5)) # Add padding below

        # --- REMOVED Save Button ---

def run_Data_Anonymizer_GUI():
    global root, text_input # Make sure they are accessible globally
    root = tk.Tk()
    root.title("Data Anonymizer (Auto Save)")

    frame = tk.Frame(root)
    frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    global text_input
    text_input = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=80, height=20)
    text_input.pack(fill=tk.BOTH, expand=True, pady=(0, 5)) # Expand text area

    button_frame = tk.Frame(frame) # Frame for buttons
    button_frame.pack(fill=tk.X)

    upload_button = tk.Button(button_frame, text="Upload Text File", command=upload_file)
    upload_button.pack(side=tk.LEFT, padx=(0, 5), pady=5) # Pack side-by-side

    process_button = tk.Button(button_frame, text="Process Text", command=process_gui)
    process_button.pack(side=tk.LEFT, pady=5)

    # --- on_close function ---
    # Just destroys the window. Saving happens in process_gui now.
    def on_close():
        print("Closing application.")
        root.destroy()
        # sys.exit(0) # Optional: uncomment to force exit if needed

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

# ================================
# End Updated Data_Anonymizer_GUI.py code (Auto Save)
# ================================


# (The remaining parts of your code for console-based operations remain unchanged below)
# ... (keep the run_Name_and_Address_Removal, run_Phone_Number_Removal, etc. functions as they were) ...
# ... (keep the __main__ block as it was, calling run_Data_Anonymizer_GUI first) ...

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
        # Attempt to redact first name, last name, and full name if found elsewhere
        try:
            parts = name.split()
            first_name = parts[0]
            last_name = parts[-1]
            # Create variants carefully, avoid overly broad matches
            name_variants = [re.escape(name)] # Full name first
            if len(parts) > 1:
                 name_variants.extend([re.escape(first_name), re.escape(last_name)])
                 # Add common titles (optional, can be expanded)
                 name_variants.append(rf"(?:Mr|Ms|Mrs|Dr)\.?\s*{re.escape(last_name)}")
            else: # Only one name part found
                 name_variants.append(re.escape(first_name))

            # Use word boundaries to avoid partial matches within other words
            name_pattern = r"\b(?:" + "|".join(name_variants) + r")\b"
            # Perform case-insensitive replacement
            text = re.sub(name_pattern, "[REDACTED]", text, flags=re.IGNORECASE)
        except IndexError:
             print(f"Warning: Could not properly split name '{name}' for redaction.")
             # Fallback: just redact the exact name string if splitting fails
             text = re.sub(r"\b" + re.escape(name) + r"\b", "[REDACTED]", text, flags=re.IGNORECASE)

    # Note: Address redaction beyond the specific "Address:" line is complex and not implemented here.
    return text


def run_Name_and_Address_Removal():
    print("\nPlease paste your document text. Enter a blank line to finish:")
    lines = []
    while True:
        try:
            line = input()
            if line == "":
                break
            lines.append(line)
        except EOFError: # Handle case where input stream ends unexpectedly
             break
    text = "\n".join(lines)
    if not text.strip():
         print("No text entered.")
         return
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
        print(f"Error: Input file not found: {input_file}")
        return None
    except PermissionError:
        print(f"Error: Permission denied for file: {input_file}")
        return None
    except Exception as e:
        print(f"Unexpected error reading file {input_file}: {e}")
        return None

def anonymize_phone_PhoneRemoval(content):
    pattern = re.compile(r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
    return pattern.sub("*phone*", content)

# --- Placeholder functions for PhoneRemoval ---
def anonymize_name_PhoneRemoval(content): return content
def anonymize_address_PhoneRemoval(content): return content
def anonymize_dob_PhoneRemoval(content): return content
def anonymize_ssn_PhoneRemoval(content): return content
def anonymize_email_PhoneRemoval(content): return content

def run_Phone_Number_Removal():
    # IMPORTANT: Update these paths or make them dynamic (e.g., use input())
    input_file = r"C:\Users\llama\OneDrive\Desktop\input.txt" # Example path
    output_file = r"C:\Users\llama\OneDrive\Desktop\output.txt" # Example path
    print(f"\nAttempting phone number removal from: {input_file}")
    content = read_file(input_file)
    if content is not None:
        # Only anonymize phone numbers in this specific function run
        content = anonymize_phone_PhoneRemoval(content)
        # The other placeholder functions don't modify the content
        content = anonymize_name_PhoneRemoval(content)
        content = anonymize_address_PhoneRemoval(content)
        content = anonymize_dob_PhoneRemoval(content)
        content = anonymize_ssn_PhoneRemoval(content)
        content = anonymize_email_PhoneRemoval(content)
        try:
            with open(output_file, 'w', encoding='utf-8') as outfile:
                outfile.write(content)
            print("Phone number anonymization complete. Output saved to:", output_file)
        except Exception as e:
            print(f"Error writing output file {output_file}: {e}")

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
    # Use a function for replacement to handle the logic sequentially
    replaced_count = 0
    def replace_date(match):
        nonlocal replaced_count
        replacement = ""
        if replaced_count == 0:
             replacement = "dob"
        elif replaced_count == 1:
             replacement = "date_of_visit"
        else:
             replacement = "date"
        replaced_count += 1
        return replacement

    # Use re.sub with the replacement function
    # We need to be careful here. re.sub replaces *all* occurrences found by the pattern.
    # To replace sequentially (dob, date_of_visit, date), we need a more complex approach
    # than a single re.sub call if the pattern can match multiple times.

    # Let's revert to the iterative find and replace approach, ensuring we don't get stuck
    matches = list(re.finditer(pattern, text)) # Find all matches with positions
    new_text_parts = []
    last_end = 0
    replaced_count = 0
    for match in matches:
        start, end = match.span()
        # Add the text segment before the current match
        new_text_parts.append(text[last_end:start])

        # Determine the replacement string
        if replaced_count == 0:
            replacement = "dob"
        elif replaced_count == 1:
            replacement = "date_of_visit"
        else:
            replacement = "date"
        new_text_parts.append(replacement)
        replaced_count += 1
        last_end = end # Update the end position

    # Add the remaining text after the last match
    new_text_parts.append(text[last_end:])

    return "".join(new_text_parts)


def anonymize_medical_number_all(text):
    return re.sub(r"\b\d{7}\b", "medical number", text)

def anonymize_all(text):
    text = remove_name_and_address(text) # Removes lines starting with Name:/Patient: or Address:
    # Name redaction within the text body is handled by anonymize_text_NameAddress if needed, but not called here.
    # This function focuses on removing specific lines and replacing patterns.
    text = anonymize_phone_all(text)
    text = anonymize_email_all(text)
    text = anonymize_dates(text) # Handles dob, date_of_visit, date
    text = anonymize_medical_number_all(text)
    return text

def run_remove_sensitive_data():
    print("\n--- Remove Sensitive Data (from file) ---")
    try:
        file_path = input("Enter path to the text file: ").strip()
        # Basic check if path is empty
        if not file_path:
            print("No file path entered.")
            return

        data = read_file(file_path)
        if data is None: # read_file handles errors and returns None
             return # Stop if file reading failed

        cleaned = anonymize_all(data) # Apply the combined anonymization
        print("\n--- Cleaned Data ---")
        print(cleaned)

        # Optionally ask to save the cleaned data
        save_cleaned = input("Save the cleaned data? (y/n): ").strip().lower()
        if save_cleaned == 'y':
            # Suggest a default output filename based on the input filename
            base_name = os.path.basename(file_path)
            name, ext = os.path.splitext(base_name)
            default_output_name = f"{name}_cleaned{ext}"

            output_path = filedialog.asksaveasfilename(
                title="Save Cleaned Data",
                initialdir=os.path.dirname(file_path), # Start in the same directory
                initialfile=default_output_name,
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            if output_path:
                try:
                     with open(output_path, "w", encoding="utf-8") as f_out:
                          f_out.write(cleaned)
                     print(f"Cleaned data saved to: {output_path}")
                except Exception as e:
                     print(f"Error saving cleaned file: {e}")

    except Exception as e:
         # Catch any other unexpected errors during the process
         print(f"An unexpected error occurred in run_remove_sensitive_data: {e}")


if __name__ == "__main__":
    # Run the GUI part first. The script will wait here until the GUI window is closed.
    run_Data_Anonymizer_GUI()

    # --- Important Note ---
    # The console scripts below will only run AFTER the GUI window is manually closed.

    print("\n--- GUI Closed. Proceeding with console scripts (if any were intended to run after) ---")

    # Example: Uncomment if you want to run this after closing the GUI
    # run_Name_and_Address_Removal()

    # Example: Uncomment if you want to run this after closing the GUI
    # run_Phone_Number_Removal() # Remember this uses hardcoded paths by default

    # Example: Uncomment if you want to run this after closing the GUI
    # run_remove_sensitive_data()

    print("\n--- Script finished ---")
