# CNN-LSTM Based Intelligent Security Monitoring for LLM Applications

##  Overview

Large Language Model (LLM) applications such as AI chatbots, AI assistants, RAG systems, and AI agents are becoming increasingly popular. However, these applications are vulnerable to prompt injection attacks and suspicious user behavior.

This project introduces an intelligent security monitoring layer that uses a CNN-LSTM deep learning model to analyze user prompts before they reach the LLM. The system classifies interactions as **Normal** or **Suspicious**, logs suspicious activities in a SQLite database, and displays them through an admin dashboard for monitoring.

---

##  Problem Statement

Traditional Intrusion Detection Systems (IDS) mainly monitor network traffic and system-level attacks. They are not specifically designed to detect prompt injection attacks and suspicious interactions in LLM applications.

This project aims to improve LLM security by detecting suspicious user prompts before they are processed by the language model.

---

##  Features

* CNN-LSTM based prompt classification
* Detection of suspicious user behavior
* Prompt injection monitoring
* Groq API integration for AI responses
* SQLite database for alert logging
* Admin dashboard for monitoring security incidents
* Real-time prompt analysis

---

## 🛠️ Technologies Used

* Python
* TensorFlow / Keras
* CNN-LSTM
* Flask
* SQLite
* HTML
* CSS
* JavaScript
* NumPy
* Pandas
* Groq API
* Llama 3.1 8B Instant

---

##  Project Workflow

```text
User Prompt
      │
      ▼
Chat Application
      │
      ▼
Security Monitoring Layer
      │
      ▼
Text Preprocessing
      │
      ▼
CNN-LSTM Model
      │
      ▼
Normal / Suspicious Classification

Normal
   │
   ▼
Groq API
   │
   ▼
AI Response

Suspicious
   │
   ▼
Security Alert
   │
   ▼
SQLite Database
   │
   ▼
Admin Dashboard
```

---

##  Project Structure

```text
Project/
│── app.py
│── model/
│── dataset/
│── preprocessing/
│── static/
│── templates/
│── database/
│── dashboard/
│── requirements.txt
│── README.md
```

---

##  Installation

```bash
git clone <repository-url>

cd <project-folder>

pip install -r requirements.txt

python app.py
```

---

##  Current Project Status

| Component            | Status                             |
| -------------------- | ---------------------------------  |
| Chat Functionality   | ✅ Working                         |
| CNN-LSTM Model       | ✅ Working                         |
| Groq API Integration | ✅ Working                         |
| Dataset              | ✅ Available                       |
| SQLite Database      | ✅ Working                         |
| Admin Dashboard      | ✅ Working                         |
| Authentication       | 🚧 Planned for Future Enhancement |

---

##  Future Enhancements

* Secure admin authentication
* Larger and more diverse datasets
* Advanced behavioral analysis
* Explainable AI
* Real-time security notifications
* Enterprise deployment



