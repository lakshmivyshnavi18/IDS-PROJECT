"""
start.py  —  One-command project launcher for LLM Security Monitor.

Usage:
  python start.py           # Full launch (API + Dashboard)
  python start.py --setup   # Install deps + generate dataset + start
  python start.py --api     # API only
  python start.py --dash    # Dashboard only
"""

import sys
import os
import subprocess
import argparse
import time
from pathlib import Path

BASE_DIR = Path(__file__).parent


def run(cmd, **kwargs):
    print(f"  $ {cmd}")
    return subprocess.run(cmd, shell=True, **kwargs)


def install_deps():
    print("\n[1/4] Installing dependencies...")
    run(f"{sys.executable} -m pip install -r requirements.txt -q")
    print("  ✓ Dependencies installed")


def generate_dataset():
    print("\n[2/4] Generating dataset...")
    result = run(f"{sys.executable} data/generation/dataset_generator.py", cwd=BASE_DIR)
    if result.returncode != 0:
        print("  ⚠ Dataset generation failed — check errors above")
    else:
        print("  ✓ Dataset generated")


def start_api():
    print("\n[3/4] Starting FastAPI backend...")
    print("  URL: http://localhost:8000")
    print("  Docs: http://localhost:8000/docs")
    return subprocess.Popen(
        "uvicorn api.main:app --reload --port 8000",
        shell=True, cwd=BASE_DIR,
    )


def start_dashboard():
    print("\n[4/4] Starting Streamlit dashboard...")
    print("  URL: http://localhost:8501")
    return subprocess.Popen(
        "streamlit run dashboard/app.py --server.port 8501",
        shell=True, cwd=BASE_DIR,
    )


def main():
    parser = argparse.ArgumentParser(description="LLM Security Monitor Launcher")
    parser.add_argument("--setup", action="store_true", help="Install deps + generate dataset")
    parser.add_argument("--api", action="store_true", help="Start API server only")
    parser.add_argument("--dash", action="store_true", help="Start dashboard only")
    parser.add_argument("--train", action="store_true", help="Train CNN+LSTM model")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  🛡️  LLM Security Monitor")
    print("  Intelligent Security Monitoring using CNN-LSTM")
    print("="*60)

    # Check .env
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        print("\n  ⚠️  .env file not found!")
        print("  Copy .env.example to .env and add your GROQ_API_KEY")
        print("  The system will use mock responses without a Groq API key.\n")

    if args.setup:
        install_deps()
        generate_dataset()

    if args.train:
        print("\n[TRAIN] Training CNN+LSTM model (this may take 10-30 minutes)...")
        run(f"{sys.executable} models/cnn_lstm/trainer.py cnn_lstm", cwd=BASE_DIR)
        return

    processes = []

    if args.api:
        p = start_api()
        processes.append(p)
    elif args.dash:
        p = start_dashboard()
        processes.append(p)
    else:
        # Full launch: API first, then dashboard
        api_proc = start_api()
        processes.append(api_proc)
        time.sleep(3)  # Let API start
        dash_proc = start_dashboard()
        processes.append(dash_proc)

    if processes:
        print("\n" + "─"*60)
        print("  ✓ All services started.")
        print("  Dashboard: http://localhost:8501")
        print("  API:       http://localhost:8000")
        print("  API Docs:  http://localhost:8000/docs")
        print("\n  Press Ctrl+C to stop all services.")
        print("─"*60 + "\n")
        try:
            for p in processes:
                p.wait()
        except KeyboardInterrupt:
            print("\n  Stopping services...")
            for p in processes:
                p.terminate()
            print("  ✓ Done.")


if __name__ == "__main__":
    main()
