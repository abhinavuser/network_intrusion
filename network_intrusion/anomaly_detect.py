from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
import pandas as pd

data = pd.read_csv("traffic_data.csv")  
X = data.drop(["label"], axis=1)  

model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
model.fit(X)

data["anomaly"] = model.predict(X)
data["anomaly"] = data["anomaly"].map({1: 0, -1: 1})  # Map anomalies to 1

print("Anomaly Detection Results:")
print(classification_report(data["label"], data["anomaly"]))
