import os
import pandas as pd
import numpy as np
import pickle
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
RAW_DATA_DIR = os.path.join(BASE_DIR, "data", "raw")
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, "data", "processed")
MODEL_DIR = os.path.join(BASE_DIR, "model")

os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

MAX_WORDS = 10000
MAX_LEN = 200

def load_and_merge_data():
    df_inj = pd.read_csv(os.path.join(RAW_DATA_DIR, "deepset_prompt_injections.csv"))
    df_jail = pd.read_csv(os.path.join(RAW_DATA_DIR, "chatgpt_jailbreak_prompts.csv"))
    df_benign = pd.read_csv(os.path.join(RAW_DATA_DIR, "dolly_benign.csv"))
    
    # Preprocess Injections (Filter to only include actual injections, label 1)
    df_inj = df_inj[df_inj['label'] == 1][['text', 'label']].copy()
    
    # Preprocess Jailbreaks (Assume label 2)
    df_jail['text'] = df_jail['Prompt']
    df_jail['label'] = 2
    df_jail = df_jail[['text', 'label']].copy()
    
    # Preprocess Benign (Assume label 0)
    df_benign['text'] = df_benign['instruction'] + " " + df_benign['context'].fillna('')
    df_benign['label'] = 0
    df_benign = df_benign[['text', 'label']].copy()
    
    # Balancing: Undersample benign to 2000 records
    df_benign_sampled = df_benign.sample(n=2000, random_state=42)
    
    df_combined = pd.concat([df_benign_sampled, df_inj, df_jail], ignore_index=True)
    df_combined['text'] = df_combined['text'].astype(str)
    
    return df_combined

def preprocess_and_tokenize():
    print("Loading and merging data...")
    df = load_and_merge_data()
    texts = df['text'].to_numpy(dtype=str)
    labels = df['label'].to_numpy(dtype=int)
    
    print("Splitting data...")
    X_train_text, X_test_text, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, stratify=labels, random_state=42
    )
    
    print("Fitting tokenizer...")
    tokenizer = Tokenizer(num_words=MAX_WORDS, oov_token="<OOV>")
    tokenizer.fit_on_texts(X_train_text)
    
    print("Converting to sequences and padding...")
    X_train_seq = tokenizer.texts_to_sequences(X_train_text)
    X_test_seq = tokenizer.texts_to_sequences(X_test_text)
    
    X_train_pad = pad_sequences(X_train_seq, maxlen=MAX_LEN, padding='post', truncating='pre')
    X_test_pad = pad_sequences(X_test_seq, maxlen=MAX_LEN, padding='post', truncating='pre')
    
    print("Saving processed data...")
    np.save(os.path.join(PROCESSED_DATA_DIR, "X_train.npy"), X_train_pad)
    np.save(os.path.join(PROCESSED_DATA_DIR, "X_test.npy"), X_test_pad)
    np.save(os.path.join(PROCESSED_DATA_DIR, "y_train.npy"), y_train)
    np.save(os.path.join(PROCESSED_DATA_DIR, "y_test.npy"), y_test)
    
    print("Saving tokenizer...")
    with open(os.path.join(MODEL_DIR, "tokenizer.pkl"), "wb") as f:
        pickle.dump(tokenizer, f)
        
    print(f"Preprocessing complete. Training shape: {X_train_pad.shape}")

if __name__ == "__main__":
    preprocess_and_tokenize()
