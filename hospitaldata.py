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
        r"^(?:Patient|Name)\s*:\s*(.+)$",
        lambda m: m.group(1).strip(),
        text,
        flags=re.IGNORECASE | re.MULTILINE
    )
    text_cleaned = re.sub(
        r"^Address\s*:\s*.+$",
        "",
        text_without_name,
        flags=re.IGNORECASE | re.MULTILINE
    )
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
        text = text.replace(dob_matches[0], "dob", 1)
    return text

def anonymize_medical_number(text):
    return re.sub(r"\b\d{7}\b", "medical number", text)

def anonymize_phone(text):
    pattern = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    return re.sub(pattern, "phone", text)

def anonymize_email(text):
    pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    return re.sub(pattern, "email", text)

def process_single_record(record):
    name, address = extract_name_and_address(record)
    cleaned = remove_extracted_lines(record)
    # We do NOT anonymize DOB, phone, email here so they remain visible.
    cleaned = anonymize_medical_number(cleaned)
    return name, address, cleaned

def process_all_records(full_text):
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
    results = {
        "Dates": [],
        "Phone Numbers": [],
        "Fax Numbers": [],
        "Email Addresses": [],
        "SSN": [],
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
        "DOB": []
    }

    # Dates (DOB is the first date found)
    date_pattern = (
        r"\b\d{1,2}/\d{1,2}/\d{4}\b"
        r"|\b\d{4}-\d{2}-\d{2}\b"
        r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,2},\s\d{4}\b"
    )
    all_dates = re.findall(date_pattern, text)
    if all_dates:
        results["DOB"] = [all_dates[0]]
        results["Dates"] = all_dates[1:]
    else:
        results["Dates"] = []

    phone_pattern = r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    results["Phone Numbers"] = re.findall(phone_pattern, text)

    fax_pattern = r"(?i)\bFax(?:\s*number| no\.?)?\s*[:\-]?\s*(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    results["Fax Numbers"] = re.findall(fax_pattern, text)

    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    results["Email Addresses"] = re.findall(email_pattern, text)

    ssn_pattern = r"\b\d{3}-\d{2}-\d{4}\b"
    results["SSN"] = re.findall(ssn_pattern, text)

    med_rec_pattern_line = r"(?i)\bMedical record number\s*:\s*([^\n]+)"
    line_matches = re.findall(med_rec_pattern_line, text)
    results["Medical Record Numbers"].extend(line_matches)

    hpbn_pattern = r"(?i)\bHealth plan beneficiary number\s*:\s*([^\n]+)"
    results["Health Plan Beneficiary Numbers"] = re.findall(hpbn_pattern, text)

    account_pattern = r"(?i)\bAccount\s*:\s*([^\n]+)"
    results["Account Numbers"] = re.findall(account_pattern, text)

    cert_lic_pattern = r"(?i)\b(?:license|certificate)\s*number\s*:\s*([^\n]+)"
    results["Certificate/License Numbers"] = re.findall(cert_lic_pattern, text)

    serial_pattern = r"(?i)\bserial numbers?\s*:\s*([^\n]+)"
    results["Serial Numbers"] = re.findall(serial_pattern, text)

    device_pattern = r"(?i)\bDevice identifier\s*:\s*([^\n]+)"
    results["Device Identifiers"] = re.findall(device_pattern, text)

    url_pattern = r"(?i)\b(?:https?://\S+|www\.\S+)\b"
    results["URLs"] = re.findall(url_pattern, text)

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    results["IP Addresses"] = re.findall(ip_pattern, text)

    bio_pattern = r"(?i)\bBiometric\s*:\s*([^\n]+)"
    results["Biometric Identifiers"] = re.findall(bio_pattern, text)

    ff_pattern = r"(?i)(full face photographic images?[^\n]*)"
    results["Full Face Photographic Images"] = re.findall(ff_pattern, text)

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
    pattern = r"(?i)(?=^\s*(?:Patient\s*:\s*|Patient\s+Name\s*:\s*))"
    chunks = re.split(pattern, full_text.strip(), flags=re.MULTILINE)
    if len(chunks) <= 1 and (not chunks or not re.match(pattern, chunks[0])):
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
        text_box.pack(fill=tk.X, expand=True, pady=(0, 5))

def isolate_patient_chunk(chunk):
    lines = chunk.splitlines()
    out_lines = []
    for line in lines:
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
        text_box.pack(fill=tk.X, expand=True, pady=(0, 5))

def remove_name_and_address(text):
    text = re.sub(
        r"^(?:Patient|Patient Name|Name)\s*:\s*(.+)$",
        lambda m: m.group(1).strip(),
        text,
        flags=re.IGNORECASE | re.MULTILINE
    )
    return "\n".join([line for line in text.splitlines() if line.strip() != ""])

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
        new_text_parts.append(match.group(0))
        last_end = end
        replaced_count += 1
    new_text_parts.append(text[last_end:])
    return "".join(new_text_parts)

def anonymize_medical_number_all(text):
    return re.sub(r"\b\d{7}\b", "medical number", text)

def remove_name_and_address_again(text):
    text = re.sub(
        r"^(?:Patient|Patient Name|Name)\s*:\s*(.+)$",
        lambda m: m.group(1).strip(),
        text,
        flags=re.IGNORECASE | re.MULTILINE
    )
    return "\n".join([line for line in text.splitlines() if line.strip() != ""])

def anonymize_all(text):
    text = remove_name_and_address(text)
    # Keep the actual DOB, phone, email visible? Or you can remove them here if you wish.
    text = anonymize_medical_number_all(text)
    return text

# ============================
# The function you requested
# ============================
def process_gui_patient_info_with_full_text():
    """
    Shows the "selected fields" in the text box by default,
    but toggles to a fully anonymized entire-file text or
    the fully unmodified entire-file text when "Deidentify"/"Restore Full" is clicked.
    """
    full_text = text_input.get("1.0", tk.END)
    if not full_text.strip():
        messagebox.showerror("Error", "No text provided!")
        return

    # 1) Build the "selected fields" text as before
    all_results = process_all_records_patient_info_only(full_text)
    if not all_results:
        messagebox.showinfo("Info", "No patient info found or processed.")
        return

    selected_fields_lines = []
    for i, (name, address, all_items, _) in enumerate(all_results, start=1):
        selected_fields_lines.append(f"--- Patient Record {i} ---")
        selected_fields_lines.append(f"Name: {name if name else 'Not Found'}")
        dob_value = all_items.get("DOB", [])
        if dob_value:
            selected_fields_lines.append(f"DOB: {dob_value[0]}")
        else:
            selected_fields_lines.append("DOB: Not Found")
        selected_fields_lines.append(f"Address: {address if address else 'Not Found'}")
        # Other fields, same as before
        extra_keys = [
            "Dates", "Phone Numbers", "Fax Numbers", "Email Addresses", "SSN",
            "Medical Record Numbers", "Health Plan Beneficiary Numbers",
            "Account Numbers", "Certificate/License Numbers", "Serial Numbers",
            "Device Identifiers", "URLs", "IP Addresses", "Biometric Identifiers",
            "Full Face Photographic Images", "Unique Identifying Codes"
        ]
        for key in extra_keys:
            vals = all_items.get(key, [])
            if vals:
                selected_fields_lines.append(f"{key}: {', '.join(vals)}")
            else:
                selected_fields_lines.append(f"{key}: Not Found")
        selected_fields_lines.append("")  # blank line

    selected_fields_text = "\n".join(selected_fields_lines)

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    # ADDED CODE: Auto-save the "selected_fields_text" to __pycache__ when clicked
    try:
        cache_folder = "__pycache__"
        if not os.path.exists(cache_folder):
            os.makedirs(cache_folder)
        output_filename = "process_text_auto_save.txt"
        output_path = os.path.join(cache_folder, output_filename)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(selected_fields_text)
        messagebox.showinfo("Auto-Saved", f"Results automatically saved to:\n{output_path}")
    except Exception as e:
        messagebox.showerror("Auto-Save Error", f"Could not automatically save results:\n{e}")
    # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

    # 2) Create a Toplevel window
    output_window = tk.Toplevel(root)
    output_window.title("Patient Records (Selected Fields)")

    canvas = tk.Canvas(output_window)
    scrollbar = tk.Scrollbar(output_window, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas)
    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # 3) Frame for the scrolled text
    record_frame = tk.LabelFrame(scrollable_frame, text="Patient Records (Selected Fields)", padx=10, pady=10)
    record_frame.pack(fill="x", expand=True, padx=5, pady=5, anchor="nw")

    text_box = scrolledtext.ScrolledText(record_frame, wrap=tk.WORD, width=80, height=25)
    # Show the SELECTED FIELDS by default
    text_box.insert(tk.END, selected_fields_text)
    text_box.config(state=tk.DISABLED)
    text_box.pack(fill=tk.X, expand=True, pady=(0, 5))

    # 4) We want to let the user toggle the ENTIRE original text vs. an anonymized version
    original_full_text = full_text  # The entire file text unmodified
    # Build an anonymized version of the ENTIRE text:
    anonymized_entire_text = re.sub(r"(?im)Name:\s*.*", "Name: [DEIDENTIFIED]", original_full_text)
    anonymized_entire_text = re.sub(r"(?im)DOB:\s*.*", "DOB: [DEIDENTIFIED]", anonymized_entire_text)
    anonymized_entire_text = re.sub(r"(?im)Address:\s*.*", "Address: [DEIDENTIFIED]", anonymized_entire_text)
    anonymized_entire_text = re.sub(r"(?im)Phone:\s*.*", "Phone: [DEIDENTIFIED]", anonymized_entire_text)
    anonymized_entire_text = re.sub(r"(?im)Email:\s*.*", "Email: [DEIDENTIFIED]", anonymized_entire_text)
    anonymized_entire_text = re.sub(r"(?im)SSN:\s*.*", "SSN: [DEIDENTIFIED]", anonymized_entire_text)
    # ... etc. for other patterns you want to anonymize ...

    is_showing_selected_fields = True
    is_deidentified = False

    def on_deidentify_clicked():
        """
        1st click: If we are still showing selected fields, show anonymized entire text.
        2nd click: If we are showing anonymized entire text, show full original text.
        Then we alternate anonymized <-> original full text.
        """
        nonlocal is_showing_selected_fields, is_deidentified

        text_box.config(state=tk.NORMAL)
        text_box.delete("1.0", tk.END)

        if is_showing_selected_fields:
            # Currently showing the "selected fields".
            # Now switch to the anonymized entire text from the file.
            text_box.insert(tk.END, anonymized_entire_text)
            deidentify_button.config(text="Restore Full")
            is_showing_selected_fields = False
            is_deidentified = True
        else:
            # We are showing either anonymized or full text already:
            if is_deidentified:
                # Switch to the FULL original text
                text_box.insert(tk.END, original_full_text)
                deidentify_button.config(text="Deidentify")
                is_deidentified = False
            else:
                # Switch back to anonymized
                text_box.insert(tk.END, anonymized_entire_text)
                deidentify_button.config(text="Restore Full")
                is_deidentified = True

        text_box.config(state=tk.DISABLED)

    # 5) Single button for toggling
    deidentify_button = tk.Button(record_frame, text="Deidentify", command=on_deidentify_clicked)
    deidentify_button.pack(anchor="ne", pady=5)

def remove_name_and_address_again(text):
    return re.sub(
        r"^(?:Patient|Patient Name|Name)\s*:\s*(.+)$",
        lambda m: m.group(1).strip(),
        text,
        flags=re.IGNORECASE | re.MULTILINE
    )

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

    process_button = tk.Button(
        button_frame,
        text="Process Text",
        command=process_gui_patient_info_with_full_text
    )
    process_button.pack(side=tk.LEFT, padx=(0, 5), pady=5)

    # ---- Button "Process Text (Patient OR Patient Name)" was removed ----
    # ---- Button "Extract Patient Info (One File)" was removed ----

    def on_close():
        print("Closing application.")
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

# ---- Function process_gui_both_patient_notations() was removed ----
# ---- Function process_gui_extract_patient_info_one_file() was removed ----

def anonymize_dob_DOBRemoval(text):
    dob_pattern = r"\b\d{1,2}/\d{1,2}/\d{4}\b|\b\d{4}-\d{2}-\d{2}\b|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,2},\s\d{4}\b"
    dob_matches = re.findall(dob_pattern, text)
    if dob_matches:
        text = text.replace(dob_matches[0], "dob", 1)
    return text

def anonymize_medical_number_DOBRemoval(text):
    return re.sub(r"\b\d{7}\b", "medical number", text)

def remove_email(text):
    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    return re.sub(email_pattern, "email", text)

def anonymize_text_NameAddress(text, name, address):
    text = re.sub("Name: [REDACTED]", text, flags=re.IGNORECASE | re.MULTILINE)
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

