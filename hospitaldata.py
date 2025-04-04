import re
import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from datetime import datetime  # Used for timestamp folder in multi-patient saving

# ================================
# Begin Data_Anonymizer_GUI.py code (Auto Save)
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
    # This function remains intact, but we won't call it anymore
    dob_pattern = (
        r"\b\d{1,2}/\d{1,2}/\d{4}\b"
        r"|\b\d{4}-\d{2}-\d{2}\b"
        r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,2},\s\d{4}\b"
    )
    dob_matches = re.findall(dob_pattern, text)
    if dob_matches:
        text = text.replace(dob_matches[0], "dob", 1)
    return text

def anonymize_medical_number(text):
    return re.sub(r"\b\d{7}\b", "medical number", text)

def anonymize_phone(text):
    # This function remains, but we won't call it anymore
    pattern = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    return re.sub(pattern, "phone", text)

def anonymize_email(text):
    # This function remains, but we won't call it anymore
    pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    return re.sub(pattern, "email", text)

def process_single_record(record):
    """
    Process one 'database entry' or 'record':
      - Extract name, address
      - Remove name/address lines
      - Anonymize *some fields*
    Returns (extracted_name, extracted_address, anonymized_text).
    """
    name, address = extract_name_and_address(record)
    cleaned = remove_extracted_lines(record)

    # -- The user specifically wants DOB, phone, email to be visible,
    #    so we do NOT call anonymize_dob, anonymize_phone, or anonymize_email. --
    # cleaned = anonymize_dob(cleaned)       # <== COMMENTED OUT
    cleaned = anonymize_medical_number(cleaned)
    # cleaned = anonymize_phone(cleaned)     # <== COMMENTED OUT
    # cleaned = anonymize_email(cleaned)     # <== COMMENTED OUT

    return name, address, cleaned

def process_all_records(full_text):
    """
    Splits the text on each 'Patient:' line (ignoring case).
    This ensures that everything for ONE patient stays together.
    If there's only one 'Patient:' line, you'll only get one record.
    """
    chunks = re.split(r"(?i)(?=^\s*Patient\s*:\s*)", full_text.strip(), flags=re.MULTILINE)
    if len(chunks) <= 1 and (not chunks or not re.match(r"(?i)^\s*Patient\s*:\s*", chunks[0])):
        if not full_text.strip():
            return []
        return [process_single_record(full_text.strip())]
    results = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        if re.match(r"(?i)^\s*Patient\s*:\s*", chunk):
            name, address, anon_text = process_single_record(chunk)
            results.append((name, address, anon_text))
        elif not results and chunk.strip():
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

def extract_all_phi_items(text):
    """
    Scan the given text for all 18 HIPAA-related items.
    Returns a dictionary { "Dates": [...], "Phone Numbers": [...], etc. }
    If an item is not found, it will have an empty list.
    """
    results = {
        "Dates": [],
        "Phone Numbers": [],
        "Fax Numbers": [],
        "Email Addresses": [],
        "SSNs": [],
        "Medical Record Numbers": [],
        "Health Plan Beneficiary Numbers": [],
        "Account Numbers": [],
        "Certificate/License Numbers": [],
        "Serial Numbers": [],
        "Device Identifiers": [],
        "URLs": [],
        "IP Addresses": [],
        "Biometric Identifiers": [],
        "Full Face Photographic Images": [],
        "Unique Identifying Codes": [],
    }

    # 3) Dates
    date_pattern = (
        r"\b\d{1,2}/\d{1,2}/\d{4}\b"
        r"|\b\d{4}-\d{2}-\d{2}\b"
        r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,2},\s\d{4}\b"
    )
    results["Dates"] = re.findall(date_pattern, text)

    # 4) Phone numbers
    phone_pattern = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    results["Phone Numbers"] = re.findall(phone_pattern, text)

    # 5) Fax numbers
    fax_pattern = r"(?i)\bFax(?:\s*number| no\.?)?\s*[:\-]?\s*(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    results["Fax Numbers"] = re.findall(fax_pattern, text)

    # 6) Email addresses
    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    results["Email Addresses"] = re.findall(email_pattern, text)

    # 7) SSNs
    ssn_pattern = r"\b\d{3}-\d{2}-\d{4}\b"
    results["SSNs"] = re.findall(ssn_pattern, text)

    # 8) Medical record numbers
    med_rec_pattern_line = r"(?i)\bMedical record number\s*:\s*([^\n]+)"
    line_matches = re.findall(med_rec_pattern_line, text)
    results["Medical Record Numbers"].extend(line_matches)

    # 9) Health plan beneficiary numbers
    hpbn_pattern = r"(?i)\bHealth plan beneficiary number\s*:\s*([^\n]+)"
    results["Health Plan Beneficiary Numbers"] = re.findall(hpbn_pattern, text)

    # 10) Account numbers
    account_pattern = r"(?i)\bAccount\s*:\s*([^\n]+)"
    results["Account Numbers"] = re.findall(account_pattern, text)

    # 11) Certificate/license numbers
    cert_lic_pattern = r"(?i)\b(?:license|certificate)\s*number\s*:\s*([^\n]+)"
    results["Certificate/License Numbers"] = re.findall(cert_lic_pattern, text)

    # 12) Serial numbers
    serial_pattern = r"(?i)\bserial numbers?\s*:\s*([^\n]+)"
    results["Serial Numbers"] = re.findall(serial_pattern, text)

    # 13) Device identifiers
    device_pattern = r"(?i)\bDevice identifier\s*:\s*([^\n]+)"
    results["Device Identifiers"] = re.findall(device_pattern, text)

    # 14) URLs
    url_pattern = r"(?i)\b(?:https?://\S+|www\.\S+)\b"
    results["URLs"] = re.findall(url_pattern, text)

    # 15) IP addresses
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    results["IP Addresses"] = re.findall(ip_pattern, text)

    # 16) Biometric identifiers
    bio_pattern = r"(?i)\bBiometric\s*:\s*([^\n]+)"
    results["Biometric Identifiers"] = re.findall(bio_pattern, text)

    # 17) Full face photographic images
    ff_pattern = r"(?i)(full face photographic images?[^\n]*)"
    results["Full Face Photographic Images"] = re.findall(ff_pattern, text)

    # 18) Unique identifying code
    code_pattern = r"(?i)\bCode\s*:\s*([^\n]+)"
    results["Unique Identifying Codes"] = re.findall(code_pattern, text)

    return results

def process_single_record_with_all_info(record):
    name, address, cleaned = process_single_record(record)
    all_items = extract_all_phi_items(record)
    return name, address, all_items, cleaned

def process_all_records_with_all_info(full_text):
    chunks = re.split(r"(?i)(?=^\s*Patient\s*:\s*)", full_text.strip(), flags=re.MULTILINE)
    if len(chunks) <= 1 and (not chunks or not re.match(r"(?i)^\s*Patient\s*:\s*", chunks[0])):
        if not full_text.strip():
            return []
        return [process_single_record_with_all_info(full_text.strip())]
    results = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        if re.match(r"(?i)^\s*Patient\s*:\s*", chunk):
            name, address, all_items, anon_text = process_single_record_with_all_info(chunk)
            results.append((name, address, all_items, anon_text))
        elif not results and chunk.strip():
            name, address, all_items, anon_text = process_single_record_with_all_info(chunk)
            results.append((name, address, all_items, anon_text))
    return results

def my_process_all_records_both_notations(full_text):
    """
    Splits on EITHER 'Patient:' or 'Patient Name:' lines (case-insensitive),
    isolates the patient portion (until 'Provider:' or 'Hospital name:'),
    then calls your process_single_record_with_all_info(...) on that chunk.
    Returns a list of (name, address, all_items, anonymized_text) for each patient.
    """
    pattern = r"(?i)(?=^\s*(?:Patient\s*:\s*|Patient\s+Name\s*:\s*))"
    chunks = re.split(pattern, full_text.strip(), flags=re.MULTILINE)

    if len(chunks) <= 1 and (not chunks or not re.match(pattern, chunks[0])):
        # If no "Patient:" or "Patient Name:" found, fallback to entire text
        if not full_text.strip():
            return []
        iso_chunk = isolate_patient_chunk(full_text.strip())
        name, address, all_items, anon_text = process_single_record_with_all_info(iso_chunk)
        return [(name, address, all_items, anon_text)]

    results = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        iso_chunk = isolate_patient_chunk(chunk)
        name, address, all_items, anon_text = process_single_record_with_all_info(iso_chunk)
        results.append((name, address, all_items, anon_text))

    return results

def process_gui():
    """
    (Unchanged)
    We keep this but do not use it.
    """
    full_text = text_input.get("1.0", tk.END).strip()
    if not full_text:
        messagebox.showerror("Error", "No text provided!")
        return

    all_results = process_all_records_with_all_info(full_text)
    if not all_results:
        messagebox.showinfo("Info", "No records found or processed.")
        return

    combined_anonymized_text = []
    for i, (name, address, all_items, anon_text) in enumerate(all_results, start=1):
        record_header = f"--- Record {i} ---"
        if name:
            record_header += f" (Name: {name})"
        combined_anonymized_text.append(record_header)
        combined_anonymized_text.append(anon_text)
        combined_anonymized_text.append("\n")

    full_output_text = "\n".join(combined_anonymized_text)

    try:
        cache_folder = "__pycache__"
        if not os.path.exists(cache_folder):
            os.makedirs(cache_folder)
        output_filename = "anonymized_records_output.txt"
        output_path = os.path.join(cache_folder, output_filename)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_output_text)

        messagebox.showinfo("Auto-Saved", f"Anonymized records automatically saved to:\n{output_path}")

    except Exception as e:
        messagebox.showerror("Auto-Save Error", f"Could not automatically save results:\n{e}")

    output_window = tk.Toplevel(root)
    output_window.title("Anonymized Output (View Only)")

    canvas = tk.Canvas(output_window)
    scrollbar = tk.Scrollbar(output_window, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    for i, (name, address, all_items, anon_text) in enumerate(all_results, start=1):
        record_frame = tk.LabelFrame(scrollable_frame, text=f"Record {i}", padx=10, pady=10)
        record_frame.pack(fill="x", expand=True, padx=5, pady=5, anchor="nw")

        info_lines = []
        info_lines.append("Extracted Information:")
        info_lines.append(f"  Name: {name if name else 'Not Found'}")
        info_lines.append(f"  Address: {address if address else 'Not Found'}")

        for key, found_list in all_items.items():
            if found_list:
                joined = ", ".join(found_list)
                info_lines.append(f"  {key}: {joined}")
            else:
                info_lines.append(f"  {key}: Not Found")

        info_lines.append("")
        info_lines.append("Anonymized Text:")

        info_text = "\n".join(info_lines)
        info_label = tk.Label(record_frame, text=info_text, justify=tk.LEFT)
        info_label.pack(anchor="w", pady=(0, 5))

        text_box = scrolledtext.ScrolledText(record_frame, wrap=tk.WORD, width=70, height=10)
        text_box.insert(tk.END, anon_text)
        text_box.config(state=tk.DISABLED)
        text_box.pack(fill="x", expand=True, pady=(0, 5))

def isolate_patient_chunk(chunk):
    lines = chunk.splitlines()
    out_lines = []
    for line in lines:
        # we break if we see "Provider:" or "Hospital name:"
        if re.match(r"(?i)^\s*(Provider|Hospital name)\s*:\s*", line):
            break
        out_lines.append(line)
    return "\n".join(out_lines)

def process_all_records_patient_info_only(full_text):
    chunks = re.split(r"(?i)(?=^\s*Patient\s*:\s*)", full_text.strip(), flags=re.MULTILINE)
    if len(chunks) <= 1 and (not chunks or not re.match(r"(?i)^\s*Patient\s*:\s*", chunks[0])):
        if not full_text.strip():
            return []
        isolated_chunk = isolate_patient_chunk(full_text.strip())
        name, address, all_items, cleaned = process_single_record_with_all_info(isolated_chunk)
        return [(name, address, all_items, cleaned)]

    results = []
    for chunk in chunks:
        if not chunk.strip():
            continue
        if re.match(r"(?i)^\s*Patient\s*:\s*", chunk):
            isolated = isolate_patient_chunk(chunk)
            name, address, all_items, cleaned = process_single_record_with_all_info(isolated)
            results.append((name, address, all_items, cleaned))
        elif not results and chunk.strip():
            isolated = isolate_patient_chunk(chunk)
            name, address, all_items, cleaned = process_single_record_with_all_info(isolated)
            results.append((name, address, all_items, cleaned))
    return results

def process_gui_patient_info_only():
    full_text = text_input.get("1.0", tk.END).strip()
    if not full_text:
        messagebox.showerror("Error", "No text provided!")
        return

    all_results = process_all_records_patient_info_only(full_text)
    if not all_results:
        messagebox.showinfo("Info", "No patient info found or processed.")
        return

    combined_anonymized_text = []
    for i, (name, address, all_items, anon_text) in enumerate(all_results, start=1):
        record_header = f"--- Patient Record {i} ---"
        if name:
            record_header += f" (Name: {name})"
        combined_anonymized_text.append(record_header)
        combined_anonymized_text.append(anon_text)
        combined_anonymized_text.append("\n")

    full_output_text = "\n".join(combined_anonymized_text)

    try:
        cache_folder = "__pycache__"
        if not os.path.exists(cache_folder):
            os.makedirs(cache_folder)
        output_filename = "anonymized_records_output.txt"
        output_path = os.path.join(cache_folder, output_filename)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_output_text)

        messagebox.showinfo("Auto-Saved", f"Anonymized records automatically saved to:\n{output_path}")
    except Exception as e:
        messagebox.showerror("Auto-Save Error", f"Could not automatically save results:\n{e}")

    output_window = tk.Toplevel(root)
    output_window.title("Anonymized Output (View Only)")

    canvas = tk.Canvas(output_window)
    scrollbar = tk.Scrollbar(output_window, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)

    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    for i, (name, address, all_items, anon_text) in enumerate(all_results, start=1):
        record_frame = tk.LabelFrame(scrollable_frame, text=f"Patient Record {i}", padx=10, pady=10)
        record_frame.pack(fill="x", expand=True, padx=5, pady=5, anchor="nw")

        info_lines = []
        info_lines.append("Extracted Patient Information:")
        info_lines.append(f"  Name: {name if name else 'Not Found'}")
        info_lines.append(f"  Address: {address if address else 'Not Found'}")
        for key, found_list in all_items.items():
            if found_list:
                joined = ", ".join(found_list)
                info_lines.append(f"  {key}: {joined}")
            else:
                info_lines.append(f"  {key}: Not Found")

        info_lines.append("")
        info_lines.append("Anonymized Text:")

        info_text = "\n".join(info_lines)
        info_label = tk.Label(record_frame, text=info_text, justify=tk.LEFT)
        info_label.pack(anchor="w", pady=(0, 5))

        text_box = scrolledtext.ScrolledText(record_frame, wrap=tk.WORD, width=70, height=10)
        text_box.insert(tk.END, anon_text)
        text_box.config(state=tk.DISABLED)
        text_box.pack(fill="x", expand=True, pady=(0, 5))

# Helpers for full-text anonymization
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
    replaced_count = 0
    matches = list(re.finditer(pattern, text))
    new_text_parts = []
    last_end = 0
    for match in matches:
        start, end = match.span()
        new_text_parts.append(text[last_end:start])
        # Keep the date visible by appending match.group(0)
        new_text_parts.append(match.group(0))
        last_end = end
        replaced_count += 1
    new_text_parts.append(text[last_end:])
    return "".join(new_text_parts)

def anonymize_medical_number_all(text):
    return re.sub(r"\b\d{7}\b", "medical number", text)

def remove_name_and_address(text):
    text = re.sub(r"^(?:Patient|Name)\s*:\s*.+$", "", text, flags=re.IGNORECASE | re.MULTILINE)
    text = re.sub(r"^Address\s*:\s*.+$", "", text, flags=re.IGNORECASE | re.MULTILINE)
    text = "\n".join([line for line in text.splitlines() if line.strip() != ""])
    return text

def anonymize_all(text):
    # Keep the function, but comment out phone/email/date anonymization so user can see them.
    text = remove_name_and_address(text)
    # text = anonymize_phone_all(text)
    # text = anonymize_email_all(text)
    # text = anonymize_dates(text)
    text = anonymize_medical_number_all(text)
    return text

def process_gui_patient_info_with_full_text():
    full_text = text_input.get("1.0", tk.END).strip()
    if not full_text:
        messagebox.showerror("Error", "No text provided!")
        return

    all_results = process_all_records_patient_info_only(full_text)
    if not all_results:
        messagebox.showinfo("Info", "No patient info found or processed.")
        return

    anonymized_full_text = anonymize_all(full_text)

    try:
        cache_folder = "__pycache__"
        if not os.path.exists(cache_folder):
            os.makedirs(cache_folder)
        output_filename = "full_anonymized_output.txt"
        output_path = os.path.join(cache_folder, output_filename)

        # Append mode so we don't overwrite previous runs:
        with open(output_path, "a", encoding="utf-8") as f:
            f.write("\n\n--- New run on {} ---\n".format(datetime.now()))
            f.write(anonymized_full_text)
            f.write("\n--- End of run ---\n")

        messagebox.showinfo("Auto-Saved", f"Full anonymized text appended to:\n{output_path}")
    except Exception as e:
        messagebox.showerror("Auto-Save Error", f"Could not automatically save results:\n{e}")

    output_window = tk.Toplevel(root)
    output_window.title("Anonymized Full Text - With Patient Info Extracted")

    canvas = tk.Canvas(output_window)
    scrollbar = tk.Scrollbar(output_window, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)

    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    for i, (name, address, all_items, _) in enumerate(all_results, start=1):
        record_frame = tk.LabelFrame(scrollable_frame, text=f"Patient Record {i}", padx=10, pady=10)
        record_frame.pack(fill="x", expand=True, padx=5, pady=5, anchor="nw")

        info_lines = []
        info_lines.append("Extracted Patient Information:")
        info_lines.append(f"  Name: {name if name else 'Not Found'}")
        info_lines.append(f"  Address: {address if address else 'Not Found'}")
        for key, found_list in all_items.items():
            if found_list:
                joined = ", ".join(found_list)
                info_lines.append(f"  {key}: {joined}")
            else:
                info_lines.append(f"  {key}: Not Found")

        info_lines.append("")
        info_lines.append("Anonymized Text (Full File):")

        info_text = "\n".join(info_lines)
        info_label = tk.Label(record_frame, text=info_text, justify=tk.LEFT)
        info_label.pack(anchor="w", pady=(0, 5))

        text_box = scrolledtext.ScrolledText(record_frame, wrap=tk.WORD, width=70, height=10)
        text_box.insert(tk.END, anonymized_full_text)
        text_box.config(state=tk.DISABLED)
        text_box.pack(fill="x", expand=True, pady=(0, 5))

def process_gui_extract_patient_info_one_file():
    """
    Splits text on 'Patient:' or 'Patient Name:' lines (both notations)
    using our new 'my_process_all_records_both_notations' function.
    For each chunk, extracts Name, Address, 18 HIPAA items,
    then auto-saves them all in a single text file: "patient_info_extracted.txt"
    """
    full_text = text_input.get("1.0", tk.END).strip()
    if not full_text:
        messagebox.showerror("Error", "No text provided!")
        return

    all_results = my_process_all_records_both_notations(full_text)
    if not all_results:
        messagebox.showinfo("Info", "No patient info found or processed.")
        return

    lines_to_save = []
    for i, (name, address, all_items, anon_text) in enumerate(all_results, start=1):
        lines_to_save.append(f"--- Patient Record {i} ---")
        lines_to_save.append(f"Name: {name if name else 'Not Found'}")
        lines_to_save.append(f"Address: {address if address else 'Not Found'}")

        # Show each of the 18 HIPAA keys if found
        relevant_keys = [
            "Dates",
            "Phone Numbers",
            "Fax Numbers",
            "Email Addresses",
            "SSNs",
            "Medical Record Numbers",
            "Health Plan Beneficiary Numbers",
            "Account Numbers",
            "Certificate/License Numbers",
            "Serial Numbers",
            "Device Identifiers",
            "URLs",
            "IP Addresses",
            "Biometric Identifiers",
            "Full Face Photographic Images",
            "Unique Identifying Codes",
        ]
        for key in relevant_keys:
            values = all_items.get(key, [])
            if values:
                lines_to_save.append(f"{key}: {', '.join(values)}")
            else:
                lines_to_save.append(f"{key}: Not Found")

        lines_to_save.append("")  # blank line

    output_text = "\n".join(lines_to_save)
    try:
        cache_folder = "__pycache__"
        if not os.path.exists(cache_folder):
            os.makedirs(cache_folder)
        output_filename = "patient_info_extracted.txt"
        output_path = os.path.join(cache_folder, output_filename)

        # We append instead of overwrite so we don't lose older runs.
        with open(output_path, "a", encoding="utf-8") as f:
            f.write("\n\n--- New run on {} ---\n".format(datetime.now()))
            f.write(output_text)
            f.write("\n--- End of run ---\n")

        messagebox.showinfo("Auto-Saved", f"Patient info appended to:\n{output_path}")
    except Exception as e:
        messagebox.showerror("Auto-Save Error", f"Could not save extracted info:\n{e}")

    out_window = tk.Toplevel(root)
    out_window.title("Patient Info Extracted - One File")

    st_box = scrolledtext.ScrolledText(out_window, wrap=tk.WORD, width=80, height=25)
    st_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    st_box.insert(tk.END, output_text)
    st_box.config(state=tk.DISABLED)

def run_Data_Anonymizer_GUI():
    global root, text_input
    root = tk.Tk()
    root.title("Data Anonymizer (Auto Save)")

    frame = tk.Frame(root)
    frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    global text_input
    text_input = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=80, height=20)
    text_input.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

    button_frame = tk.Frame(frame)
    button_frame.pack(fill=tk.X)

    upload_button = tk.Button(button_frame, text="Upload Text File", command=upload_file)
    upload_button.pack(side=tk.LEFT, padx=(0, 5), pady=5)

    # "Process Text" => anonymize the full text with patient extraction (already appends entire file)
    process_button = tk.Button(
        button_frame,
        text="Process Text",
        command=process_gui_patient_info_with_full_text
    )
    process_button.pack(side=tk.LEFT, padx=(0, 5), pady=5)

    # (Comment out multiple-patients button – but do not delete function if it existed.)
    # multi_button = tk.Button(
    #     button_frame,
    #     text="Process & Save Multiple Patients",
    #     command=process_gui_save_multiple_patients
    # )
    # multi_button.pack(side=tk.LEFT, padx=(0, 5), pady=5)

    # *** UPDATED: "Process Text (Patient OR Patient Name)" => now displays entire anonymized file. ***
    button_both = tk.Button(
        button_frame,
        text="Process Text (Patient OR Patient Name)",
        command=lambda: process_gui_both_patient_notations()
    )
    button_both.pack(side=tk.LEFT, padx=(0, 5), pady=5)

    extract_info_button = tk.Button(
        button_frame,
        text="Extract Patient Info (One File)",
        command=process_gui_extract_patient_info_one_file
    )
    extract_info_button.pack(side=tk.LEFT, padx=(0,5), pady=5)

    def on_close():
        print("Closing application.")
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

def process_gui_both_patient_notations():
    """
    A new function that uses 'my_process_all_records_both_notations' to detect
    'Patient:' or 'Patient Name:'. Then displays results in the same style.
    
    -- UPDATED so that the "Anonymized Text" area shows the entire anonymized file
       rather than just the patient-chunk.
    """
    full_text = text_input.get("1.0", tk.END).strip()
    if not full_text:
        messagebox.showerror("Error", "No text provided!")
        return

    # We still do chunk-based extraction (for name/address/all_items). 
    # But for the final "Anonymized Text," we'll use the entire anonymized file.
    all_results = my_process_all_records_both_notations(full_text)

    if not all_results:
        messagebox.showinfo("Info", "No records found or processed.")
        return

    # Anonymize the entire text (instead of just a chunk)
    anonymized_full_text = anonymize_all(full_text)

    # Build the combined text for the text file output (if you want to save it)
    combined_anonymized_text = []
    for i, (name, address, all_items, anon_text) in enumerate(all_results, start=1):
        record_header = f"--- Record {i} ---"
        if name:
            record_header += f" (Name: {name})"
        combined_anonymized_text.append(record_header)
        # Instead of adding `anon_text`, add the full anonymized text:
        combined_anonymized_text.append(anonymized_full_text)
        combined_anonymized_text.append("\n")

    full_output_text = "\n".join(combined_anonymized_text)

    try:
        cache_folder = "__pycache__"
        if not os.path.exists(cache_folder):
            os.makedirs(cache_folder)
        output_filename = "anonymized_records_patientName.txt"
        output_path = os.path.join(cache_folder, output_filename)

        # We'll open in append mode, just as we did before.
        with open(output_path, "a", encoding="utf-8") as f:
            f.write("\n\n--- New run on {} ---\n".format(datetime.now()))
            f.write(full_output_text)
            f.write("\n--- End of run ---\n")

        messagebox.showinfo("Auto-Saved", f"(Patient OR Patient Name) data appended to:\n{output_path}")

    except Exception as e:
        messagebox.showerror("Auto-Save Error", f"Could not automatically save results:\n{e}")

    # Show it in a window:
    output_window = tk.Toplevel(root)
    output_window.title("Anonymized Output (Both Notations)")

    canvas = tk.Canvas(output_window)
    scrollbar = tk.Scrollbar(output_window, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)

    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # We can still show the extracted info from each chunk, but for "Anonymized Text," we now show the entire file.
    for i, (name, address, all_items, anon_text) in enumerate(all_results, start=1):
        record_frame = tk.LabelFrame(scrollable_frame, text=f"Record {i}", padx=10, pady=10)
        record_frame.pack(fill="x", expand=True, padx=5, pady=5, anchor="nw")

        info_lines = []
        info_lines.append("Extracted Information (Both Notations):")
        info_lines.append(f"  Name: {name if name else 'Not Found'}")
        info_lines.append(f"  Address: {address if address else 'Not Found'}")

        for key, found_list in all_items.items():
            if found_list:
                joined = ", ".join(found_list)
                info_lines.append(f"  {key}: {joined}")
            else:
                info_lines.append(f"  {key}: Not Found")

        info_lines.append("")
        info_lines.append("Anonymized Text (Full File):")

        info_text = "\n".join(info_lines)
        info_label = tk.Label(record_frame, text=info_text, justify=tk.LEFT)
        info_label.pack(anchor="w", pady=(0, 5))

        text_box = scrolledtext.ScrolledText(record_frame, wrap=tk.WORD, width=70, height=10)
        # Now show the entire anonymized file here instead of just the chunk.
        text_box.insert(tk.END, anonymized_full_text)
        text_box.config(state=tk.DISABLED)
        text_box.pack(fill="x", expand=True, pady=(0, 5))

# ================================
# End Data_Anonymizer_GUI.py code
# ================================

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
        try:
            parts = name.split()
            first_name = parts[0]
            last_name = parts[-1]
            name_variants = [re.escape(name)]
            if len(parts) > 1:
                name_variants.extend([re.escape(first_name), re.escape(last_name)])
                name_variants.append(rf"(?:Mr|Ms|Mrs|Dr)\.?\s*{re.escape(last_name)}")
            else:
                name_variants.append(re.escape(first_name))

            name_pattern = r"\b(?:" + "|".join(name_variants) + r")\b"
            text = re.sub(name_pattern, "[REDACTED]", text, flags=re.IGNORECASE)
        except IndexError:
            print(f"Warning: Could not properly split name '{name}' for redaction.")
            text = re.sub(r"\b" + re.escape(name) + r"\b", "[REDACTED]", text, flags=re.IGNORECASE)
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
        except EOFError:
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

def anonymize_name_PhoneRemoval(content): return content
def anonymize_address_PhoneRemoval(content): return content
def anonymize_dob_PhoneRemoval(content): return content
def anonymize_ssn_PhoneRemoval(content): return content
def anonymize_email_PhoneRemoval(content): return content

def run_Phone_Number_Removal():
    input_file = r"C:\Users\llama\OneDrive\Desktop\input.txt"
    output_file = r"C:\Users\llama\OneDrive\Desktop\output.txt"
    print(f"\nAttempting phone number removal from: {input_file}")
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
            print("Phone number anonymization complete. Output saved to:", output_file)
        except Exception as e:
            print(f"Error writing output file {output_file}: {e}")

def run_remove_sensitive_data():
    print("\n--- Remove Sensitive Data (from file) ---")
    try:
        file_path = input("Enter path to the text file: ").strip()
        if not file_path:
            print("No file path entered.")
            return
        data = read_file(file_path)
        if data is None:
            return
        cleaned = anonymize_all(data)
        print("\n--- Cleaned Data ---")
        print(cleaned)
        save_cleaned = input("Save the cleaned data? (y/n): ").strip().lower()
        if save_cleaned == 'y':
            base_name = os.path.basename(file_path)
            name, ext = os.path.splitext(base_name)
            default_output_name = f"{name}_cleaned{ext}"
            output_path = filedialog.asksaveasfilename(
                title="Save Cleaned Data",
                initialdir=os.path.dirname(file_path),
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
        print(f"An unexpected error occurred in run_remove_sensitive_data: {e}")

if __name__ == "__main__":
    run_Data_Anonymizer_GUI()
    print("\n--- GUI Closed. Proceeding with console scripts (if any) ---")
    print("\n--- Script finished ---")
