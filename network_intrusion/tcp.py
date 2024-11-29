from scapy.all import sniff
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import joblib

MODEL_PATH = "rf_model.pkl"  
model = joblib.load(MODEL_PATH)

def process_packet(packet):
    if packet.haslayer("IP"):
        features = {
            'src_ip': packet['IP'].src,
            'dst_ip': packet['IP'].dst,
            'protocol': packet['IP'].proto,
            'length': len(packet),
        }
        df = pd.DataFrame([features])
        df = pd.get_dummies(df)  
        if not set(df.columns).issubset(model.feature_names_in_):
            print("Unexpected features in live data. Model may not work correctly.")
        prediction = model.predict(df)[0]
        print(f"Packet: {features}, Prediction: {'Intrusion' if prediction == 1 else 'Normal'}")

print("Starting live packet capture...")
sniff(prn=process_packet, filter="ip", store=False)
