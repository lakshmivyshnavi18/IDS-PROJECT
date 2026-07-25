import os
import pandas as pd
from datasets import load_dataset

RAW_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "raw")
os.makedirs(RAW_DATA_DIR, exist_ok=True)

def download_datasets():
    print("Downloading Deepset Prompt Injections...")
    try:
        ds_injections = load_dataset("deepset/prompt-injections")
        df_injections = ds_injections['train'].to_pandas()
        df_injections.to_csv(os.path.join(RAW_DATA_DIR, "deepset_prompt_injections.csv"), index=False)
        print(f"Saved {len(df_injections)} injection records.")
    except Exception as e:
        print(f"Failed to download deepset/prompt-injections: {e}")

    print("Downloading Jailbreak Chat Prompts...")
    try:
        ds_jailbreak = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts")
        df_jailbreak = ds_jailbreak['train'].to_pandas()
        df_jailbreak.to_csv(os.path.join(RAW_DATA_DIR, "chatgpt_jailbreak_prompts.csv"), index=False)
        print(f"Saved {len(df_jailbreak)} jailbreak records.")
    except Exception as e:
        print(f"Failed to download rubend18/ChatGPT-Jailbreak-Prompts: {e}")

    print("Downloading Benign Dataset (Databricks Dolly)...")
    try:
        ds_dolly = load_dataset("databricks/databricks-dolly-15k")
        df_dolly = ds_dolly['train'].to_pandas()
        df_dolly.to_csv(os.path.join(RAW_DATA_DIR, "dolly_benign.csv"), index=False)
        print(f"Saved {len(df_dolly)} benign records.")
    except Exception as e:
        print(f"Failed to download databricks/databricks-dolly-15k: {e}")

if __name__ == "__main__":
    download_datasets()
