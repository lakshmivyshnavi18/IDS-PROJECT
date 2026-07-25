import os
import numpy as np
import tensorflow as tf
from cnn_lstm import build_cnn_lstm_model

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, "data", "processed")
MODEL_DIR = os.path.join(BASE_DIR, "model")

MAX_WORDS = 10000
MAX_LEN = 200
NUM_CLASSES = 3

def train():
    print("Loading preprocessed data...")
    X_train = np.load(os.path.join(PROCESSED_DATA_DIR, "X_train.npy"))
    y_train = np.load(os.path.join(PROCESSED_DATA_DIR, "y_train.npy"))
    X_test = np.load(os.path.join(PROCESSED_DATA_DIR, "X_test.npy"))
    y_test = np.load(os.path.join(PROCESSED_DATA_DIR, "y_test.npy"))
    
    print("Building model...")
    model = build_cnn_lstm_model(MAX_WORDS, MAX_LEN, NUM_CLASSES)
    
    print("Starting training...")
    history = model.fit(
        X_train, y_train,
        epochs=5,  # 5 epochs for speed during dev
        batch_size=32,
        validation_data=(X_test, y_test)
    )
    
    print("Saving model...")
    model.save(os.path.join(MODEL_DIR, "ids_cnn_lstm.h5"))
    print("Model trained and saved to ids_cnn_lstm.h5")

if __name__ == "__main__":
    train()
