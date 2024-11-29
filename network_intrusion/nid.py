from scapy.all import rdpcap
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Step 1: Load TCP/IP dump
def load_pcap(file_path):
    packets = rdpcap(file_path)
    data = []
    for pkt in packets:
        if pkt.haslayer('IP'):
            data.append({
                'src_ip': pkt['IP'].src,
                'dst_ip': pkt['IP'].dst,
                'protocol': pkt['IP'].proto,
                'length': len(pkt)
            })
    return pd.DataFrame(data)

# Step 2: Preprocessing
def preprocess_data(df):
    df['protocol'] = df['protocol'].astype(int)
    df = pd.get_dummies(df, columns=['src_ip', 'dst_ip', 'protocol'])
    return df

# Step 3: Train model
def train_model(X, y):
    model = RandomForestClassifier()
    model.fit(X, y)
    return model

# Step 4: Main Execution
if __name__ == "__main__":
    # Load dataset
    pcap_data = load_pcap('sample.pcap')  # Replace with your file
    print("Loaded data:", pcap_data.head())

    # Simulate labels for the example (0: normal, 1: intrusion)
    pcap_data['label'] = [0] * int(len(pcap_data) * 0.8) + [1] * int(len(pcap_data) * 0.2)

    # Preprocess data
    X = preprocess_data(pcap_data.drop('label', axis=1))
    y = pcap_data['label']

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train model
    model = train_model(X_train, y_train)
    print("Model trained!")

    # Test model
    predictions = model.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, predictions))
