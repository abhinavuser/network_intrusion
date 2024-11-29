from scapy.all import rdpcap, TCP, UDP, ICMP
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Step 1: Load TCP/IP dump
def load_pcap(file_path):
    logging.info("Loading PCAP file...")
    packets = rdpcap(file_path)
    data = []
    for pkt in packets:
        if pkt.haslayer('IP'):
            pkt_data = {
                'src_ip': pkt['IP'].src,
                'dst_ip': pkt['IP'].dst,
                'protocol': pkt['IP'].proto,
                'length': len(pkt),
            }
            # Extract additional fields if available
            if pkt.haslayer(TCP):
                pkt_data.update({
                    'src_port': pkt[TCP].sport,
                    'dst_port': pkt[TCP].dport,
                    'flags': str(pkt[TCP].flags),
                })
            elif pkt.haslayer(UDP):
                pkt_data.update({
                    'src_port': pkt[UDP].sport,
                    'dst_port': pkt[UDP].dport,
                })
            elif pkt.haslayer(ICMP):
                pkt_data.update({'icmp_type': pkt[ICMP].type})
            data.append(pkt_data)
    return pd.DataFrame(data)

# Step 2: Preprocessing
def preprocess_data(df):
    logging.info("Preprocessing data...")
    # Fill missing values for ports and flags
    df['src_port'] = df.get('src_port', pd.Series([0] * len(df))).fillna(0).astype(int)
    df['dst_port'] = df.get('dst_port', pd.Series([0] * len(df))).fillna(0).astype(int)
    df['flags'] = df.get('flags', pd.Series(['None'] * len(df))).fillna('None')
    df['icmp_type'] = df.get('icmp_type', pd.Series([0] * len(df))).fillna(0).astype(int)
    
    # Convert categorical columns to dummy variables
    df = pd.get_dummies(df, columns=['src_ip', 'dst_ip', 'protocol', 'flags'])
    return df

# Step 3: Train model with hyperparameter tuning
def train_model(X, y):
    logging.info("Training the model...")
    model = RandomForestClassifier()
    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [10, 20, None],
        'min_samples_split': [2, 5, 10],
    }
    grid_search = GridSearchCV(model, param_grid, cv=3, scoring='accuracy', n_jobs=-1)
    grid_search.fit(X, y)
    logging.info(f"Best Parameters: {grid_search.best_params_}")
    return grid_search.best_estimator_

# Step 4: Main Execution
if __name__ == "__main__":
    # Load dataset
    file_path = 'http_PPI.cap'  # Replace with your file
    pcap_data = load_pcap(file_path)
    if pcap_data.empty:
        logging.error("No data extracted from PCAP. Please check the file.")
        exit()

    logging.info(f"Loaded {len(pcap_data)} packets")
    print(pcap_data.head())

    # Simulate labels for the example (0: normal, 1: intrusion)
    # Assuming unusual protocols or large payloads as potential intrusions
    pcap_data['label'] = pcap_data['length'].apply(lambda x: 1 if x > 1000 else 0)

    # Preprocess data
    X = preprocess_data(pcap_data.drop('label', axis=1))
    y = pcap_data['label']

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    logging.info(f"Training data size: {X_train.shape}, Testing data size: {X_test.shape}")

    # Train model
    model = train_model(X_train, y_train)
    logging.info("Model trained successfully!")

    # Test model
    predictions = model.predict(X_test)
    logging.info("Testing completed!")
    
    # Output results
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))
    print("\nClassification Report:")
    print(classification_report(y_test, predictions))
