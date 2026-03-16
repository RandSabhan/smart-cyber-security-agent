
Python#!/usr/bin/env python3
import yara
import os
from datetime import datetime

RULES_PATH = "rules/malware_rules.yar"

def scan_with_yara(file_path):
    print(f"[*] فحص YARA: {file_path}")
    
    if not os.path.exists(file_path):
        print("❌ الملف غير موجود")
        return
    
    rules = yara.compile(filepath=RULES_PATH)
    matches = rules.match(file_path)
    
    if matches:
        print("🚨 تم الكشف عن مؤشرات خبيثة!")
        for match in matches:
            print(f"   → القاعدة: {match.rule}")
    else:
        print("✅ الملف نظيف حسب YARA")
    
    return bool(matches)

if __name__ == "__main__":
    sample = "samples/test.exe"
    scan_with_yara(sample)
