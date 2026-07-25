import os
import numpy as np
import pickle
import re
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from ..models.base import Conversation

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, "ids_engine", "model", "ids_cnn_lstm.h5")
TOKENIZER_PATH = os.path.join(BASE_DIR, "ids_engine", "model", "tokenizer.pkl")

model = None
tokenizer = None

def load_ids_model():
    global model, tokenizer
    if os.path.exists(MODEL_PATH) and os.path.exists(TOKENIZER_PATH):
        try:
            model = load_model(MODEL_PATH)
            with open(TOKENIZER_PATH, "rb") as f:
                tokenizer = pickle.load(f)
            print("IDS Model loaded successfully.")
        except Exception as e:
            print(f"Error loading model: {e}")
    else:
        print("Model or tokenizer not found. Run training first.")

HEURISTIC_BLOCKLIST = [
    # Reverse Shell & Remote Access
    "reverse shell", "nc -e", "netcat", "ncat", "bash -i", "/dev/tcp",
    "python -c 'import socket", "msfvenom", "metasploit", "payload",
    "monitor in kali", "kali linux", "remote access", "bind shell",
    "powershell -nop", "invoke-webrequest", "iex(", "downloadstring",

    # Jailbreak & Prompt Injection
    "ignore all instructions", "ignore previous instructions", "ignore your instructions",
    "bypass restrictions", "disregard instructions", "forget your instructions",
    "you are now", "act as", "pretend you are", "roleplay as", "dan mode",
    "jailbreak", "ignore your training", "do anything now",

    # System Prompt Extraction
    "system prompt", "reveal your prompt", "show me your instructions",
    "what are your instructions", "print your system message",

    # Hacking Tools & Recon
    "nmap", "sqlmap", "burpsuite", "hydra", "john the ripper", "aircrack",
    "wireshark", "tcpdump", "nikto", "gobuster", "dirb", "masscan",

    # Malware & Exploits
    "malware", "ransomware", "trojan", "keylogger", "rootkit", "spyware",
    "exploit", "zero-day", "buffer overflow", "sql injection", "xss attack",
    "csrf attack", "privilege escalation", "lateral movement",

    # Data Exfiltration
    "exfiltrate", "steal credentials", "dump database", "extract passwords",
    "credential dumping", "mimikatz",
]

REGEX_PATTERNS = {
    "Base64 Payload": r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    "Hidden IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
}

def check_prompt_security(prompt: str) -> dict:
    global model, tokenizer
    
    # Layer 1: Heuristic / Signature-based Detection
    prompt_lower = prompt.lower()
    for keyword in HEURISTIC_BLOCKLIST:
        if keyword in prompt_lower:
            return {
                "is_malicious": True,
                "attack_type": "jailbreak (signature)",
                "confidence": 1.0,
                "severity": "Critical"
            }
            
    # Layer 1.5: Regex Pattern Matching
    for attack_type, pattern in REGEX_PATTERNS.items():
        if re.search(pattern, prompt):
            return {
                "is_malicious": True,
                "attack_type": attack_type,
                "confidence": 0.99,
                "severity": "High"
            }

    # Layer 2: Machine Learning Detection (CNN-LSTM)
    if model is None or tokenizer is None:
        load_ids_model()
        
    result = {
        "is_malicious": False,
        "attack_type": "benign",
        "confidence": 0.0,
        "severity": "Low"
    }
    
    if model and tokenizer:
        try:
            seq = tokenizer.texts_to_sequences([prompt])
            padded = pad_sequences(seq, maxlen=200, padding='post', truncating='pre')
            pred = model.predict(padded, verbose=0)[0]
            
            class_idx = np.argmax(pred)
            result["confidence"] = float(pred[class_idx])
            
            if class_idx == 1:
                result["is_malicious"] = True
                result["attack_type"] = "prompt_injection"
                result["severity"] = "High"
            elif class_idx == 2:
                result["is_malicious"] = True
                result["attack_type"] = "jailbreak"
                result["severity"] = "Critical"
                
        except Exception as e:
            print(f"IDS Inference Error: {e}")

    print(f"Logged -> Prompt: {prompt[:30]}... | Type: {result['attack_type']} | Conf: {result['confidence']:.2f}")
    return result

# Trigger loading on startup
load_ids_model()
