# Bài tập Git

- **Người thực hiện:** Phạm Thanh Sơn
- **MSSV:** 235480106099
- **Deadline:** 28/09/2026 23:59

---

# Môn An toàn và bảo mật thông tin.

## a.Tìm hiểu thuật toán mã hóa hiện đại DES và AES

### 1. Thuật toán mã hóa DES (Data Encryption Standard)


# Tìm hiểu thuật toán mã hóa hiện đại DES và AES

## 1. Thuật toán mã hóa DES (Data Encryption Standard)

### Tổng quan & Thông số kỹ thuật
* **Kích thước khối (Block size):** 64 bit.
* **Độ dài khóa (Key length):** 64 bit (Thực tế chỉ dùng 56 bit làm khóa thực sự, 8 bit còn lại dùng để kiểm tra chẵn lẻ - parity bit).
* **Cấu trúc:** Mạng Feistel gồm 16 vòng lập (rounds).

### Quy trình mã hóa
1. **Hoán vị ban đầu (Initial Permutation - IP):** Khối dữ liệu 64 bit đầu vào được hoán vị vị trí các bit, sau đó tách thành 2 nửa 32 bit: Nửa trái ($L_0$) và Nửa phải ($R_0$).
2. **16 vòng Feistel ($i = 1 \dots 16$):** Tại mỗi vòng $i$, dữ liệu biến đổi theo công thức:
   $$L_i = R_{i-1}$$
   $$R_i = L_{i-1} \oplus F(R_{i-1}, K_i)$$
   *(Trong đó: $\oplus$ là phép toán XOR bit; $K_i$ là khóa con 48 bit sinh ra từ khóa chính).*
   * **Hàm Feistel $F(R_{i-1}, K_i)$ bao gồm 4 bước:**
     * *Mở rộng (Expansion - E):* Biến đổi $R_{i-1}$ từ 32 bit thành 48 bit.
     * *Cộng khóa con:* XOR kết quả 48 bit với khóa con $K_i$.
     * *Thay thế (S-Boxes):* Chia 48 bit thành 8 nhóm (mỗi nhóm 6 bit), đi qua 8 hộp thay thế S-Box phi tuyến để nén thành 32 bit.
     * *Hoán vị (P-Box):* Hoán vị 32 bit thu được từ S-Boxes.
3. **Hoán vị đảo (Inverse Initial Permutation - $IP^{-1}$):** Sau vòng 16, hai nửa $L_{16}$ và $R_{16}$ được đảo vị trí thành $(R_{16}, L_{16})$, ghép lại thành 64 bit và đưa qua bảng hoán vị $IP^{-1}$ để ra bản mã (Ciphertext).

### Quy trình giải mã
DES sử dụng cùng một thuật toán với quá trình mã hóa, chỉ khác là các khóa con $K_i$ được áp dụng theo thứ tự ngược lại (từ $K_{16}$ giảm dần về $K_1$).

---

## 2. Thuật toán mã hóa AES (Advanced Encryption Standard)

### Tổng quan & Thông số kỹ thuật
* **Kích thước khối (Block size):** Cố định 128 bit (16 bytes), biểu diễn dưới dạng ma trận trạng thái $4 \times 4$ bytes (State matrix).
* **Độ dài khóa linh hoạt:**
  * **AES-128:** Khóa 128 bit $\rightarrow$ 10 vòng lập (rounds).
  * **AES-192:** Khóa 192 bit $\rightarrow$ 12 vòng lập.
  * **AES-256:** Khóa 256 bit $\rightarrow$ 14 vòng lập.
* **Cấu trúc:** Mạng thay thế - hoán vị (SPN - Substitution-Permutation Network).

### Quy trình mã hóa (Ví dụ với AES-128: 10 vòng)
1. **Mở rộng khóa (Key Expansion):** Sinh 11 khóa con vòng $K_0, K_1, \dots, K_{10}$ (mỗi khóa 128 bit) từ khóa chính ban đầu bằng thuật toán Rijndael Key Schedule.
2. **Vòng khởi tạo (Round 0):** `AddRoundKey` - XOR ma trận trạng thái đầu vào với khóa con ban đầu $K_0$.
3. **9 vòng lặp chính (Round 1 đến Round 9):** Mỗi vòng biến đổi qua 4 bước:
   * **SubBytes (Thay thế byte):** Thay từng byte trong ma trận trạng thái bằng một byte tương ứng trong bảng S-Box phi tuyến trên trường Galois $GF(2^8)$.
   * **ShiftRows (Dịch hàng):** Dịch chuyển vòng các byte trên mỗi hàng của ma trận trạng thái:
     * *Hàng 0:* Giữ nguyên.
     * *Hàng 1:* Dịch trái 1 byte.
     * *Hàng 2:* Dịch trái 2 bytes.
     * *Hàng 3:* Dịch trái 3 bytes.
   * **MixColumns (Trộn cột):** Nhân đại số từng cột của ma trận trạng thái với một đa thức cố định trên trường $GF(2^8)$.
   * **AddRoundKey (Cộng khóa vòng):** XOR ma trận trạng thái hiện tại với khóa con $K_i$ của vòng đó.
4. **Vòng cuối cùng (Round 10):** Thực hiện 3 bước: `SubBytes` $\rightarrow$ `ShiftRows` $\rightarrow$ `AddRoundKey` (bỏ qua bước `MixColumns`). Kết quả thu được là bản mã 128 bit.

### Quy trình giải mã
Giải mã AES thực hiện các thao tác ngược (Inverse operations) theo thứ tự ngược lại:
$$\text{AddRoundKey} \rightarrow \text{InvShiftRows} \rightarrow \text{InvSubBytes} \rightarrow \text{AddRoundKey} \rightarrow \text{InvMixColumns} \rightarrow \dots$$

---

## 3. Cài đặt AES trên Python

### Yêu cầu cài đặt thư viện
```bash
pip install pycryptodome

**Chương trình mã hóa và giải mã văn bản bằng AES (chế độ CBC)**
'''bash
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class AESCipher:

  def __init__(self, key: str):
    # Khóa được chuẩn hóa về 32 bytes cho AES-256
    self.key = key.encode('utf-8').ljust(32, b'\0')[:32]

  def encrypt(self, raw_text: str) -> str:
    # Tạo IV (Initialization Vector) ngẫu nhiên 16 bytes
    iv = os.urandom(16)
    cipher = AES.new(self.key, AES.MODE_CBC, iv)

    # Đệm dữ liệu (padding) theo chuẩn PKCS7 và mã hóa
    padded_data = pad(raw_text.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)

    # Ghép IV + Chuỗi mã hóa và chuyển sang dạng Base64
    return base64.b64encode(iv + encrypted_bytes).decode('utf-8')

  def decrypt(self, enc_text: str) -> str:
    # Giải mã từ Base64
    data = base64.b64decode(enc_text)
    iv = data[:16]  # Lấy 16 bytes đầu làm IV
    encrypted_bytes = data[16:]

    cipher = AES.new(self.key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_bytes)

    # Loại bỏ padding và trả về văn bản gốc
    return unpad(decrypted_padded, AES.block_size).decode('utf-8')


# --- Demo chạy thử chương trình ---
if __name__ == '__main__':
  secret_key = 'MySecretKey123'
  message = 'Phạm Thanh Sơn - MSSV: 235480106099'

  aes = AESCipher(secret_key)

  # Mã hóa
  encrypted = aes.encrypt(message)
  print(f'Văn bản gốc    : {message}')
  print(f'Bản mã (Base64): {encrypted}')

  # Giải mã
  decrypted = aes.decrypt(encrypted)
  print(f'Bản giải mã    : {decrypted}')


![<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/fea26049-9291-4b72-9320-0ad528f08876" />](ket-qua.png)