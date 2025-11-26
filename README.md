# 🕷️ SPIDER – Scan & Port Inspection: Discovery & Exploitation Report

SPIDER is a powerful **web-based port scanner and web vulnerability detection tool** designed for cybersecurity learners, ethical hackers, network administrators, and IT professionals.
It provides fast scanning, clean UI, real-time results, and detailed reports — all powered by **Nmap + Django + Redis + TailwindCSS**.

---

## 🌟 Features

### 🔹 **IP Address & Domain Scanning**

Scan any IPv4 address or domain name with ease.

### 🔹 **Port Scanning (Nmap Engine)**

Supports multiple modes:

* Common Ports
* Top Ports
* Full Range
* Custom Range

### 🔹 **Service & Version Detection**

Detects open ports and identifies common services like HTTP, FTP, SSH, MySQL, etc.

### 🔹 **Web Vulnerability Analysis**

Basic web checks such as:

* Missing security headers
* Server exposure
* Open directory listing
* HTTP response inspection

### 🔹 **Asynchronous Scanning (Celery + Redis)**

Scans run in the background without blocking the UI.

### 🔹 **Real-Time Results**

Ports appear instantly as:

* **Open**
* **Closed**
* **Filtered**

### 🔹 **Scan History & Reporting**

Every scan is saved and can be:

* Revisited
* Exported as **PDF**, **CSV**, or **JSON**

### 🔹 **Secure Input Validation**

All inputs are validated to prevent misuse or injection attacks.

---

## 🛠️ Technology Stack

### **Frontend**

* HTML
* TailwindCSS
* JavaScript

### **Backend**

* Django (Python)
* Redis (Message Broker)
* Celery (Async Worker)

### **Core Engine**

* Nmap (Python Integration)

### **Database**

* SQLite (Dev)
* MySQL (Production)

---

## 🚀 Getting Started

### ✅ Prerequisites

Make sure these are installed:

* Python 3.8+
* Nmap
* Redis

---

## ⚙️ Installation

### 1️⃣ Clone the repository

```bash
git clone https://github.com/Neo-Ayush-jha/SPIDER.git
cd SPIDER
```

### 2️⃣ Create & activate virtual environment

```bash
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
```

### 3️⃣ Install requirements

```bash
pip install -r requirements.txt
```

### 4️⃣ Apply database migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

### 5️⃣ Start Redis server

```bash
redis-server
```

### 6️⃣ Run Celery worker

```bash
celery -A spider worker --loglevel=info
```

### 7️⃣ Run Django development server

```bash
python manage.py runserver
```

Now open:
👉 **http://127.0.0.1:8000/**

---

## 📂 Project Structure

```
SPIDER/
├─ spider/
│  ├─ __init__.py
│  ├─ settings.py
│  ├─ celery.py
│  ├─ urls.py
│  └─ wsgi.py
├─ scanner/
│  ├─ migrations/
│  ├─ templates/
│  │  └─ scanner/
│  │     └─ index.html
│  ├─ static/
│  ├─ models.py
│  ├─ tasks.py
│  ├─ views.py
│  ├─ urls.py
│  └─ admin.py
├─ manage.py
└─ requirements.txt
```

---

## 🤝 Contributing

Contributions are welcome!
Feel free to open issues or submit pull requests for improvements or new features.

---

## 🔗 Connect With Me

**Portfolio:** https://ayush-jha.netlify.app/
**GitHub:** https://github.com/Neo-Ayush-jha
**Project Link:** https://github.com/Neo-Ayush-jha/SPIDER

---
