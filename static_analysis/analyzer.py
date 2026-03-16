
#!/usr/bin/env python3
import os
import sys
import hashlib
import pefile
import yara
import json
from datetime import datetime

RULES_PATH = "rules/malware_rules.yar"

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            data = f.read(65536)
            if not data: break
            sha256.update(data)
    return sha256.hexdigest()

def scan_with_yara(file_path):
    try:
        rules = yara.compile(filepath=RULES_PATH)
        matches = rules.match(file_path)
        return [m.rule for m in matches] if matches else []
    except:
        return []

def analyze_file(file_path):
    print(f"[*] بدء التحليل الكامل: {file_path}")
    
    if not os.path.exists(file_path):
        print("❌ الملف غير موجود")
        return
    
    results = {
        "file_name": os.path.basename(file_path),
        "file_size": os.path.getsize(file_path),
        "sha256": calculate_hash(file_path),
        "scan_time": datetime.now().isoformat(),
        "yara_matches": scan_with_yara(file_path)
    }
    
    # PE Analysis
    try:
        pe = pefile.PE(file_path)
        results["is_pe"] = True
        results["sections"] = len(pe.sections)
        results["suspicious"] = False
        
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip('\x00')
            entropy = section.get_entropy()
            if entropy > 7.0:
                results["suspicious"] = True
        pe.close()
        
    except:
        results["is_pe"] = False
    
    # حفظ التقرير
    report_path = f"reports/report_{results['sha256'][:8]}.json"
    os.makedirs("reports", exist_ok=True)
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    
    print(f"[+] تم حفظ التقرير: {report_path}")
    print(f"   YARA: {'🚨 خبيث' if results['yara_matches'] else '✅ نظيف'}")
    print(f"   PE مشبوه: {'نعم' if results.get('suspicious', False) else 'لا'}")

    print("\n===== Analysis Summary =====")
    print(f"File Name : {results['file_name']}")
    print(f"File Size : {results['file_size']} bytes")
    print(f"SHA256    : {results['sha256']}")
    print(f"Is PE     : {results.get('is_pe', False)}")
    print(f"Sections  : {results.get('sections', 'N/A')}")
    print("============================")

if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <file_to_analyze>")
        sys.exit(1)

    target_file = sys.argv[1]
    analyze_file(target_file)
