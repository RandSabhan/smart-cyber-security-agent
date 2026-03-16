print("هذا ملف اختبار بسيط للتحليل الثابت فقط")
print("malware trojan cmd.exe powershell keylogger CreateProcess")

# عشان نعمل entropy عالي شوي (random bytes)
import os
with open("random_bytes.bin", "wb") as f:
    f.write(os.urandom(20000))  # ~20KB عشوائي → entropy مرتفع
