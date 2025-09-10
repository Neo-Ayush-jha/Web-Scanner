# Web-Based IP Address and Port Scanner 💻🔍

This project is a web-based IP address and port scanner application built to provide a simple, user-friendly interface for network scanning. It's an ideal tool for cybersecurity learners, network administrators, and IT professionals who need to perform quick scans without using command-line tools.

---

## 🌟 Features

* [cite_start]**IP Address & Domain Scanning:** Scan a single IPv4 address or a domain name[cite: 54, 65, 68].
* [cite_start]**Port Range Selection:** Choose from predefined port ranges like "Common Ports," "All Ports," or set a custom range[cite: 56, 89].
* [cite_start]**Asynchronous Scanning:** Scan tasks are handled asynchronously using Celery to prevent the web server from blocking and to provide a seamless user experience[cite: 71, 74].
* [cite_start]**Real-Time Results:** View scan results as they come in, displaying the status of each port as "Open," "Closed," or "Filtered"[cite: 57, 59].
* [cite_start]**Service Detection:** The scanner identifies and displays the associated service (e.g., HTTP, SSH) for commonly known open ports[cite: 60, 84].
* [cite_start]**Scan History & Reporting:** The application saves a history of scans, which can be revisited and exported in formats like PDF or CSV[cite: 61, 93, 94].
* [cite_start]**Security & Input Validation:** All user inputs are validated to prevent injection attacks, and the Nmap process runs with the lowest possible privileges[cite: 99, 100].

---

## 🛠️ Technology Stack

* [cite_start]**Frontend:** HTML, CSS, JavaScript (The SRS document mentions React.js, but for this project's simplicity, basic HTML/CSS/JS with a framework like TailwindCSS is also an option)[cite: 118, 370].
* [cite_start]**Backend:** Python with the Django framework[cite: 52, 119].
* [cite_start]**Database:** SQLite (for development) or MySQL (for production)[cite: 120, 371].
* [cite_start]**Asynchronous Task Queue:** Celery with Redis as a message broker[cite: 52, 74].
* [cite_start]**Core Scanning Engine:** Nmap, integrated via a Python library like `python-nmap`[cite: 43, 75].

---

## 🚀 Getting Started

### Prerequisites

* Python 3.8+
* Nmap
* Redis

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Neo-Ayush-jha/Web-Scanner.git](https://github.com/Neo-Ayush-jha/Web-Scanner.git)
    cd web-based-ip-scanner
    ```

2.  **Set up a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up the database:**
    ```bash
    python manage.py makemigrations scanner
    python manage.py migrate
    ```

5.  **Start the Redis server** (or any other message broker).

6.  **Run the Celery worker:**
    ```bash
    celery -A ipscanner worker --loglevel=info
    ```
    (Note: You might need to adjust this command based on your specific setup).

7.  **Run the Django development server:**
    ```bash
    python manage.py runserver
    ```

Now, navigate to `http://127.0.0.1:8000/` in your browser to access the application.

---

## 📂 Project Structure
``
ipscanner/
├─ ipscanner/
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
``
---

## 💡 Contributing

Contributions are welcome! If you have suggestions for new features, improvements, or bug fixes, feel free to open an issue or submit a pull request.

---
