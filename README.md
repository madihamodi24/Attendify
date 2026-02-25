# 📱 QR Based Attendance System

> A secure and automated attendance management system using session-based QR codes to eliminate manual attendance, prevent proxy entries, and generate accurate reports.

---

## ✨ Features

- 🔐 Secure teacher authentication
- 📷 Session-based unique QR code generation
- ⏳ Time-bound QR codes with scan limits
- 📱 One Device – One Attendance rule
- 📊 Teacher dashboard with analytics
- 🗂️ Session history & report management
- 📄 Auto-generated attendance sheets
- 🧾 Defaulter reports

---

## 🛠️ Tech Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python, Flask
- **Database:** MySQL
- **Others:** JSON, QR Code Library

---

## 🚀 Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/QR-Attendance-System.git
cd QR-Attendance-System

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Setup MySQL database
mysql -u root -p -e "CREATE DATABASE qr_attendance;"
mysql -u root -p qr_attendance < database/schema.sql

# Run the app
python app.py

```

### Update QR URL

Open `templates/dashboard.html` and replace `YOUR_IP_ADDRESS` with your actual IP:

```javascript
const qrData = `http://YOUR_IP_ADDRESS:5000/attendance-form?...`;
```

#### Example:

If your IP is 192.168.1.105, then change it to:

```JavaScript
const qrData = `http://192.168.1.105:5000/attendance-form?...`;
```

## ⚙️ How It Works

1. Teacher logs in and selects class & subject  
2. System generates a **time-bound QR code**  
3. Students scan the QR to mark attendance  
4. System verifies device, session & time rules  
5. Attendance is stored securely in the database  
6. Teacher downloads reports from the dashboard