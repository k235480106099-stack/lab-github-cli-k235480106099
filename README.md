\# Bài tập Git

\## Người thực hiện

Phạm Thanh Sơn - MSSV: k235480106099

\## Deadline

28/09/2026 23:59



\# 1. Tìm hiểu thuật toán mã hóa hiện đại DES, AES



\## 1. Thuật toán mã hóa DES (Data Encryption Standard)



\### Tổng quan và thông số kỹ thuật

\- \*\*Kích thước khối (Block size):\*\* 64 bit.

\- \*\*Độ dài khóa (Key length):\*\* 64 bit (thực tế 56 bit làm khóa thực sự, 8 bit còn lại dùng để kiểm tra chẵn lẻ - parity bit).

\- \*\*Cấu trúc:\*\* Mạng Feistel gồm 16 vòng lặp (rounds).



\### Quy trình mã hóa

1\. \*\*Hoán vị ban đầu (Initial Permutation - IP):\*\*  

&#x20;  Khối dữ liệu 64 bit đầu vào được hoán vị vị trí các bit theo một bảng cố định, sau đó tách thành 2 nửa 32 bit:

&#x20;  - Nửa trái: $L\_0$

&#x20;  - Nửa phải: $R\_0$



2\. \*\*16 vòng Feistel ($i = 1 \\dots 16$):\*\*  

&#x20;  Tại mỗi vòng $i$, dữ liệu được biến đổi theo công thức:

&#x20;  $$L\_i = R\_{i-1}$$

&#x20;  $$R\_i = L\_{i-1} \\oplus F(R\_{i-1}, K\_i)$$

&#x20;  

&#x20;  \*Trong đó:\*

&#x20;  - $\\oplus$ là phép toán XOR bit.

&#x20;  - $K\_i$ là khóa con 48 bit được sinh ra từ khóa chính 56 bit cho vòng thứ $i$.

&#x20;  - $F(R\_{i-1}, K\_i)$ là hàm Feistel thực hiện các bước:

&#x20;    - \*\*Mở rộng (Expansion - E):\*\* Biến đổi $R\_{i-1}$ từ 32 bit thành 48 bit.

&#x20;    - \*\*Cộng khóa con:\*\* XOR kết quả 48 bit với khóa con $K\_i$.

&#x20;    - \*\*Thay thế (S-Boxes):\*\* Chia 48 bit thành 8 nhóm (mỗi nhóm 6 bit), đi qua 8 hộp thay thế S-Box phi tuyến để nén thành 32 bit.

&#x20;    - \*\*Hoán vị (P-Box):\*\* Hoán vị vị trí 32 bit thu được từ S-Boxes.



3\. \*\*Hoán vị đảo (Inverse Initial Permutation - $IP^{-1}$):\*\*  

&#x20;  Sau vòng 16, hai nửa $L\_{16}$ và $R\_{16}$ được đảo vị trí thành $(R\_{16}, L\_{16})$, ghép lại thành 64 bit và đưa qua bảng hoán vị $IP^{-1}$ để ra bản mã (Ciphertext).



\### Quy trình giải mã

Giải mã DES sử dụng cùng một thuật toán với quá trình mã hóa, chỉ khác là các khóa con $K\_i$ được áp dụng theo thứ tự ngược lại (từ $K\_{16}$ giảm dần về $K\_1$).



\---



\## 2. Thuật toán mã hóa AES (Advanced Encryption Standard)



\### Tổng quan và thông số kỹ thuật

\- \*\*Kích thước khối (Block size):\*\* Cố định 128 bit (16 bytes, được biểu diễn dưới dạng ma trận trạng thái $4 \\times 4$ bytes gọi là State matrix).

\- \*\*Độ dài khóa linh hoạt:\*\*

&#x20; - \*\*AES-128:\*\* Khóa 128 bit $\\rightarrow$ 10 vòng lặp (rounds).

&#x20; - \*\*AES-192:\*\* Khóa 192 bit $\\rightarrow$ 12 vòng lặp.

&#x20; - \*\*AES-256:\*\* Khóa 256 bit $\\rightarrow$ 14 vòng lặp.

\- \*\*Cấu trúc:\*\* Mạng thay thế - hoán vị (SPN - Substitution-Permutation Network).



\### Quy trình mã hóa (Ví dụ với AES-128: 10 vòng)

1\. \*\*Mở rộng khóa (Key Expansion):\*\*  

&#x20;  Sinh 11 khóa con vòng $K\_0, K\_1, \\dots, K\_{10}$ (mỗi khóa 128 bit) từ khóa chính ban đầu bằng thuật toán Rijndael Key Schedule.



2\. \*\*Vòng khởi tạo (Round 0):\*\*  

&#x20;  - `AddRoundKey`: XOR ma trận trạng thái đầu vào với khóa con ban đầu $K\_0$.



3\. \*\*9 vòng lặp chính (Round 1 đến Round 9):\*\*  

&#x20;  Mỗi vòng biến đổi qua 4 bước:

&#x20;  - `SubBytes` (Thay thế byte): Thay từng byte trong ma trận trạng thái bằng một byte tương ứng trong bảng S-Box phi tuyến trên trường Galois $GF(2^8)$.

&#x20;  - `ShiftRows` (Dịch hàng): Dịch chuyển vòng các byte trên mỗi hàng của ma trận:

&#x20;    - Hàng 0: Giữ nguyên.

&#x20;    - Hàng 1: Dịch trái 1 byte.

&#x20;    - Hàng 2: Dịch trái 2 bytes.

&#x20;    - Hàng 3: Dịch trái 3 bytes.

&#x20;  - `MixColumns` (Trộn cột): Nhân đại số từng cột của ma trận trạng thái với một đa thức cố định trên $GF(2^8)$.

&#x20;  - `AddRoundKey` (Cộng khóa vòng): XOR ma trận trạng thái hiện tại với khóa con $K\_i$ của vòng đó.



4\. \*\*Vòng cuối cùng (Round 10):\*\*  

&#x20;  Thực hiện 3 bước `SubBytes` $\\rightarrow$ `ShiftRows` $\\rightarrow$ `AddRoundKey` (\*\*bỏ qua bước `MixColumns`\*\*). Kết quả thu được là bản mã 128 bit.



\### Quy trình giải mã

Giải mã AES thực hiện các thao tác ngược (Inverse operations) theo thứ tự ngược lại:  

`AddRoundKey` $\\rightarrow$ `InvShiftRows` $\\rightarrow$ `InvSubBytes` $\\rightarrow$ `AddRoundKey` $\\rightarrow$ `InvMixColumns` $\\rightarrow \\dots$



\---



\## 3. Cài đặt AES trên Python



Dưới đây là chương trình mã hóa và giải mã văn bản bằng AES chế độ CBC (Cipher Block Chaining) với thư viện `pycryptodome`.



\### Yêu cầu cài đặt thư viện

```bash

pip install pycryptodome

