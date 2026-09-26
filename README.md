# Bài tập Git

- **Người thực hiện:** Phạm Thanh Sơn
- **MSSV:** 235480106099
- **Deadline:** 28/09/2026 23:59

---

# Môn An toàn và bảo mật thông tin.

## a.Tìm hiểu thuật toán mã hóa hiện đại DES và AES


### Tìm hiểu thuật toán mã hóa hiện đại DES và AES

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
```

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/fea26049-9291-4b72-9320-0ad528f08876" />

---

## b. Thuật toán mã hóa bất đối xứng RSA

### 1. Khái niệm & Tổng quan
RSA (được đặt tên theo ba tác giả Rivest, Shamir và Adleman) là thuật toán mã hóa bất đối xứng (khóa công khai) phổ biến nhất hiện nay.
* **Nguyên lý độ an toàn:** Dựa trên độ khó tính toán của bài toán **phân tích một số nguyên cực lớn thành tích của hai số nguyên tố**.
* **Đặc điểm:** Sử dụng một cặp khóa riêng biệt:
  * **Khóa công khai (Public Key):** Bất kỳ ai cũng có thể biết, dùng để **mã hóa** thông điệp hoặc **kiểm tra** chữ ký số.
  * **Khóa bí mật (Private Key):** Chỉ người sở hữu giữ bí mật, dùng để **giải mã** thông điệp hoặc **tạo** chữ ký số.

---

### 2. Nguyên lý sinh cặp khóa (Key Generation)

Quy trình sinh cặp khóa công khai $(e, n)$ và bí mật $(d, n)$ trải qua 5 bước toán học sau:

b1. **Chọn hai số nguyên tố lớn ngẫu nhiên:** Chọn $p$ và $q$ ($p \neq q$).
b2. **Tính tích Modulus $n$:**
   $$n = p \times q$$
   *(Độ dài bit của $n$ chính là độ dài của khóa RSA, ví dụ: 2048-bit hoặc 4096-bit).*
b3. **Tính hàm số Euler $\phi(n)$:**
   $$\phi(n) = (p - 1)(q - 1)$$
b4. **Chọn số mũ công khai $e$ (Public Exponent):**
   * Chọn $e$ sao cho $1 < e < \phi(n)$ và $e$ nguyên tố cùng nhau với $\phi(n)$ (tức $\gcd(e, \phi(n)) = 1$).
   * *(Trong thực tế, người ta thường chọn giá trị chuẩn $e = 65537$).*
b5. **Tính số mũ bí mật $d$ (Private Exponent):**
   * Tính $d$ là nghịch đảo nhân modular của $e$ theo modulo $\phi(n)$, thỏa mãn:
     $$d \times e \equiv 1 \pmod{\phi(n)}$$
   * *(Dùng thuật toán Euclid mở rộng để tìm $d$).*

**Kết quả cặp khóa:**
* **Khóa công khai (Public Key):** $PU = \{e, n\}$
* **Khóa bí mật (Private Key):** $PR = \{d, n\}$

---

### 3. Quy trình Mã hóa và Giải mã

* **Quy trình Mã hóa (Encryption):**
  * Muốn gửi bản rõ $M$ ($M < n$), người gửi dùng **Khóa công khai** $\{e, n\}$ của người nhận để tính bản mã $C$:
    $$C = M^e \pmod n$$

* **Quy trình Giải mã (Decryption):**
  * Người nhận dùng **Khóa bí mật** $\{d, n\}$ của mình để khôi phục lại bản rõ $M$ từ bản mã $C$:
    $$M = C^d \pmod n$$

---

### 4. Ví dụ minh họa bằng số nhỏ

4.1. **Sinh khóa:**
   * Chọn $p = 61$ và $q = 53$.
   * Tính $n = 61 \times 53 = 3233$.
   * Tính $\phi(n) = (61 - 1) \times (53 - 1) = 60 \times 52 = 3120$.
   * Chọn $e = 17$ (thỏa mãn $\gcd(17, 3120) = 1$).
   * Tính $d$: $17 \times d \equiv 1 \pmod{3120} \Rightarrow d = 2753$.
   * **Khóa public:** $\{17, 3233\}$, **Khóa private:** $\{2753, 3233\}$.

4.2. **Mã hóa & Giải mã bản rõ $M = 65$:**
   * **Mã hóa:** $C = 65^{17} \pmod{3233} = 2790$.
   * **Giải mã:** $M = 2790^{2753} \pmod{3233} = 65$ *(Trùng khớp với bản gốc)*.