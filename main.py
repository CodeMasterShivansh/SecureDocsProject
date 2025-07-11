import os
import re
import pyzipper
from PIL import Image, ImageDraw, ImageFont
from PyPDF2 import PdfReader, PdfWriter
import pikepdf
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

MASKED_IP_PREFIX = "MASKED_IP"
HOST_MASK_PREFIX = "HOST"
watermark_text = "CONFIDENTIAL"
font_path = "arial.ttf"

# -----------[ Create Watermark PDF (used for PDF watermarking) ]----------- #
def create_watermark_pdf(watermark_text, output="watermark.pdf"):
    c = canvas.Canvas(output, pagesize=letter)
    c.setFont("Helvetica", 36)
    c.setFillColorRGB(0.6, 0.6, 0.6, alpha=0.3)
    c.drawString(100, 500, watermark_text)
    c.save()

# -----------[ IP & Hostname Masking ]----------- #
def mask_ip_and_host(content):
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    host_pattern = re.compile(r'\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,6}\b')

    masked_ips = {}
    masked_hosts = {}
    ip_count = 1
    host_count = 1

    def ip_replacer(match):
        nonlocal ip_count
        ip = match.group(0)
        if ip not in masked_ips:
            masked_ips[ip] = f"{MASKED_IP_PREFIX}.{ip_count}"
            ip_count += 1
        return masked_ips[ip]

    def host_replacer(match):
        nonlocal host_count
        host = match.group(0)
        if host not in masked_hosts:
            masked_hosts[host] = f"{HOST_MASK_PREFIX}_{host_count}"
            host_count += 1
        return masked_hosts[host]

    content = ip_pattern.sub(ip_replacer, content)
    content = host_pattern.sub(host_replacer, content)
    return content

# -----------[ Text/XML/Log Files ]----------- #
def process_text_file(file_path, output_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    content = mask_ip_and_host(content)
    content += f"\n\n# WATERMARK: {watermark_text}"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

# -----------[ PDF Files ]----------- #
def watermark_pdf(input_pdf, output_pdf, watermark_file="watermark.pdf"):
    watermark = PdfReader(watermark_file).pages[0]
    reader = PdfReader(input_pdf)
    writer = PdfWriter()

    for page in reader.pages:
        page.merge_page(watermark)
        writer.add_page(page)

    with open(output_pdf, "wb") as f:
        writer.write(f)

def password_protect_pdf(input_pdf, output_pdf, password):
    pdf = pikepdf.open(input_pdf)
    pdf.save(output_pdf, encryption=pikepdf.Encryption(owner=password, user=password, R=4))

# -----------[ JPG Images ]----------- #
def watermark_image(image_path, output_path):
    img = Image.open(image_path).convert("RGB")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype(font_path, 36)
    except:
        font = ImageFont.load_default()

    text_position = (10, 10)
    draw.text(text_position, watermark_text, fill=(255, 0, 0), font=font)
    img.save(output_path)

# -----------[ Password-Protected ZIP ]----------- #
def zip_with_password(file_paths, output_zip, password):
    with pyzipper.AESZipFile(output_zip, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zipf:
        zipf.setpassword(password.encode())
        for path in file_paths:
            zipf.write(path, os.path.basename(path))

# -----------[ Process All Files in Folder ]----------- #
def process_folder(input_folder, output_folder, password):
    os.makedirs(output_folder, exist_ok=True)
    processed_files = []

    for filename in os.listdir(input_folder):
        ext = filename.lower().split(".")[-1]
        input_path = os.path.join(input_folder, filename)
        output_path = os.path.join(output_folder, filename)

        if ext in ["txt", "log", "xml"]:
            process_text_file(input_path, output_path)
            processed_files.append(output_path)

        elif ext == "pdf":
            temp_pdf = os.path.join(output_folder, f"temp_{filename}")
            watermark_pdf(input_path, temp_pdf)
            password_protect_pdf(temp_pdf, output_path, password)
            os.remove(temp_pdf)
            processed_files.append(output_path)

        elif ext in ["jpg", "jpeg", "png"]:
            watermark_image(input_path, output_path)
            processed_files.append(output_path)

    # Create final password-protected zip
    zip_path = os.path.join(output_folder, "protected_output.zip")
    zip_with_password(processed_files, zip_path, password)
    print(f"\n✅ Final ZIP created at: {zip_path}")

# -----------[ Run the Project ]----------- #
if __name__ == "__main__":
    input_dir = "./BEL/input_files"        # Put your input files here
    output_dir = "./BEL/processed_output"  # Output will be saved here
    zip_password = "12345"           # Set a strong password here

    create_watermark_pdf(watermark_text)  # Create watermark.pdf once
    process_folder(input_dir, output_dir, zip_password)
"""
Currently the project does following:
-> Mask IP and Host Names only in .txt files
-> Password Protects only Pdf File and the final Zip File
-> Watermarks all types of files (.txt, .pdf, .jpg, etc.)
"""