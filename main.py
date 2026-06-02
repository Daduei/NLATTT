import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# --- CHƯƠNG 3: HIỆN THỰC HÓA ---

# 1. Tạo khóa
start_gen_key = time.time()
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
end_gen_key = time.time()

# 2. Nội dung cần ký (Giả sử đây là file văn bản của bạn)
message = b"Day la tai lieu thuc hanh chu ky so"

# 3. Thực hiện ký (Signing)
start_sign = time.time()
signature = private_key.sign(
    message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)
end_sign = time.time()

# --- CHƯƠNG 4: KẾT QUẢ ---
print("--- KET QUA THUC NGHIEM ---")
print(f"Thoi gian tao khoa: {end_gen_key - start_gen_key:.4f} giay")
print(f"Thoi gian ky so: {end_sign - start_sign:.4f} giay")
print(f"Do dai chu ky: {len(signature)} bytes")

# 4. Xác thực (Verification)
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("Xac thuc: THANH CONG (File nguyen ven)")
except Exception:
    print("Xac thuc: THAT BAI (File da bi thay doi)")