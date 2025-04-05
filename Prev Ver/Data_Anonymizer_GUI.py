import re
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

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
    text_cleaned = "\n".join(
        [line for line in text_cleaned.splitlines() if line.strip() != ""]
    )
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
    # Split whenever we encounter "Patient:" (case-insensitive),
    # but keep the delimiter in the next chunk so we don't lose "Patient:" text.
    chunks = re.split(r"(?i)(?=Patient\s*:\s*)", full_text.strip())

    # If the text does NOT contain "Patient:", treat everything as one record
    if len(chunks) == 1:
        # Means there's either no "Patient:" or just one big chunk
        return [process_single_record(chunks[0])]

    # Otherwise, we have multiple records
    results = []
    for chunk in chunks:
        # If chunk is empty, skip it
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

    # Create a new window for the results
    output_window = tk.Toplevel(root)
    output_window.title("Anonymized Output")

    # --- SCROLLABLE CONTAINER ---
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

# --- Main GUI Setup ---
root = tk.Tk()
root.title("Data Anonymizer (Multiple Records)")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

text_input = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=60, height=15)
text_input.pack()

upload_button = tk.Button(frame, text="Upload Text File", command=upload_file)
upload_button.pack(pady=5)

process_button = tk.Button(frame, text="Process Text", command=process_gui)
process_button.pack(pady=5)

root.mainloop()
