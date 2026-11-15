"""สุ่มรหัสลับให้ แล้วพิมพ์บรรทัดที่ต้องคัดลอกไปใส่ .env (ไม่ได้บันทึกอะไรลงไฟล์ อย่าส่งผลลัพธ์ให้ใคร)
ตั้งค่าครั้งแรก:      py setup_keys.py                (หรือ py setup_keys.py guardbot whitelist ถ้ามีหลายบอท)
เพิ่มบอทตัวใหม่:      py setup_keys.py --add voicebot  (ได้เฉพาะรหัสของบอทตัวนั้น ไม่แตะ SESSION_SECRET เดิม)"""
import secrets
import sys

args = sys.argv[1:]
add_mode = bool(args) and args[0] == "--add"
names = (args[1:] if add_mode else args) or ["guardbot"]
if add_mode and not args[1:]:
    sys.exit("ใช้แบบนี้: py setup_keys.py --add ชื่อบอทใหม่")
keys = {n: secrets.token_urlsafe(32) for n in names}

if add_mode:
    print("\n=== เว็บกลาง: ต่อท้ายบรรทัด BOT_KEYS ใน .env เดิม (ใส่ , คั่น) แล้วรีสตาร์ตเว็บ ===")
    print("," + ",".join(f"{n}:{k}" for n, k in keys.items()))
else:
    print("\n=== ใส่ในไฟล์ .env ของ \"เว็บกลาง\" (โฟลเดอร์ hub) ===")
    print(f"SESSION_SECRET={secrets.token_urlsafe(48)}")
    print("BOT_KEYS=" + ",".join(f"{n}:{k}" for n, k in keys.items()))
for n, k in keys.items():
    print(f"\n=== ใส่ในไฟล์ .env ของบอท \"{n}\" (รหัสต้องตรงกับด้านบน) ===")
    print(f"HUB_BOT_KEY={k}")
print()
