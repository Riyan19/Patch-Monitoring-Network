# Patch Monitoring Network

This project is a vulnerability monitoring system designed to track firmware patches and vulnerabilities (CVEs) for network devices using a **Flask** application. It provides monitoring capabilities, a dashboard, and email/Telegram notifications.

## Prerequisites

Before running the application, ensure you have the following installed:

- **Python 3.8+**
- **pip** (Python package installer)

## Installation & Setup

All application code is located in the `flask_app` directory.

### 1. Set up the Environment

Navigate to the `flask_app` directory and create a virtual environment:

```bash
cd flask_app

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

### 2. Install Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

### 3. Configuration

Create a `.env` file in the `flask_app` directory to store your configuration secrets. You can use the provided `.env-example` as a template.

**Required Environment Variables:**

```env
# NIST NVD API Key (Get one at https://nvd.nist.gov/developers/request-an-api-key)
NVD_API_KEY=your_nist_api_key

# Telegram Notification Settings
TELEGRAM_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Email Notification Settings
EMAIL_USER=your_email@example.com
EMAIL_PASS=your_email_password
SMTP_SERVER=smtp.example.com  # e.g., smtp.gmail.com
SMTP_PORT=587

# Application Settings Create your Own
SECRET_KEY=your_secret_key
EMAIL_RECIPIENT=recipient@example.com
```

### 4. Initialize the Database

The application uses a local SQLite database. It will be initialized automatically when you run the application for the first time (ensure `app.py` has the database creation logic, typically `db.create_all()`).

## Running the Application

Start the Flask development server:

```bash
python app.py
```

The application will be accessible at `http://localhost:5000` by default.

## Deployment

For production deployment, it is recommended to use a WSGI server like **Gunicorn**.

### Running with Gunicorn

```bash
# Run with 4 worker processes
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

You can also use a process manager like **Supervisor** or **Systemd** to keep the application running in the background.

## License

[Your License Here]
