import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, MaxPooling1D, LSTM, Dense, Dropout

def build_cnn_lstm_model(vocab_size, max_length, num_classes=3):
    model = Sequential([
        Embedding(input_dim=vocab_size, output_dim=128, input_length=max_length),
        
        # Spatial Feature Extraction
        Conv1D(filters=64, kernel_size=5, activation='relu'),
        MaxPooling1D(pool_size=2),
        Dropout(0.2),
        
        # Temporal/Sequential Context
        LSTM(64, return_sequences=False),
        Dropout(0.2),
        
        # Classification
        Dense(32, activation='relu'),
        Dense(num_classes, activation='softmax')
    ])
    
    model.compile(
        loss='sparse_categorical_crossentropy',
        optimizer='adam',
        metrics=['accuracy']
    )
    return model
