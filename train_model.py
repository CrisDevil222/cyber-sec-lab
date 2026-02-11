import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

# 1. Định nghĩa hàm tách từ (Thay thế cho lambda để sửa lỗi Pickle)
def custom_tokenizer(url):
    return str(url).split('.')

# 2. Dữ liệu mẫu (Dataset)
data = [
    # --- LINK SẠCH (LABEL = 0) ---
    ("google.com", 0), ("youtube.com", 0), ("facebook.com", 0),
    ("stackoverflow.com", 0), ("github.com", 0), ("wikipedia.org", 0),
    ("amazon.com", 0), ("vnexpress.net", 0), ("dantri.com.vn", 0),
    ("zingnews.vn", 0), ("shopee.vn", 0), ("tiki.vn", 0),
    ("rmit.edu.vn", 0), ("hust.edu.vn", 0), ("microsoft.com", 0),
    ("apple.com", 0), ("netflix.com", 0), ("medium.com", 0),
    
    # --- LINK PHISHING/LỪA ĐẢO (LABEL = 1) ---
    ("free-money.tk", 1), ("nhan-qua-tri-an.ga", 1),
    ("xac-thuc-tai-khoan-ngan-hang.com", 1), ("login-facebook-secure.com", 1),
    ("apple-id-support-verify.net", 1), ("paypal-security-alert.xyz", 1),
    ("tang-iphone-15-mien-phi.info", 1), ("g00gle.com-security.web.app", 1),
    ("kiem-tien-online-nhanh.club", 1), ("free-bitcoin-giveaway.net", 1),
    ("b00k-face.com", 1), ("vietcombank-xac-thuc-otp.top", 1),
    ("momo-qua-tang-tet.vip", 1), ("zalo-nhan-lixi.pro", 1)
]

# Chuyển thành DataFrame
df = pd.DataFrame(data, columns=['url', 'label'])

# 3. Xây dựng Pipeline
# Sử dụng hàm 'custom_tokenizer' đã định nghĩa ở trên thay vì lambda
pipeline = make_pipeline(
    TfidfVectorizer(tokenizer=custom_tokenizer), 
    LogisticRegression()
)

# 4. Huấn luyện mô hình (Training)
if __name__ == "__main__":
    print("⏳ Đang huấn luyện AI...")
    pipeline.fit(df['url'], df['label'])

    # 5. Lưu lại bộ não AI
    joblib.dump(pipeline, 'phishing_model.pkl')
    print("✅ Đã xong! File 'phishing_model.pkl' đã được tạo thành công.")