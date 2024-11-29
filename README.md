# **Network Intrusion and Anomaly Detection via TCP/IP Dump Analysis**

## **Project Overview**
This project aims to detect network intrusions by analyzing TCP/IP dump files. The system uses machine learning techniques to classify network traffic as normal or intrusive, helping identify potential security threats in real-time.

---

## **Key Features**
- **TCP/IP Packet Capture**: Uses Scapy to capture and analyze network traffic.
- **Machine Learning Model**: Trains a Model to detect anomalies in network traffic.
- **Real-time Sniffing**: Continuously monitors live network traffic for intrusions.
- **Web Interface**: A simple Tkinter-based GUI to run scripts.

---

## **Getting Started**

### **1. Requirements**
Install the necessary Python packages:

```bash
pip install scapy pandas scikit-learn tkinter
```

### **2. Run the Scripts**
- **Packet Capture**: Run `nid.py` to start capturing and analyzing network packets.
  
  ```bash
  python nid.py
  ```

- **Detect Anomaly**: Use `anomaly_detect.py` to train the anomaly detection model.
  
  ```bash
  python anomaly_detect.py
  ```

- **GUI Interface**: Use `gui.py` to run scripts from a graphical interface.
  
  ```bash
  python gui.py
  ```

---


## **Model Evaluation**

After training, the model generates a classification report with metrics like precision, recall, and accuracy. Example output:

```
Classification Report:
              precision    recall  f1-score   support

           0       1.00      1.00      1.00         8
           1       1.00      1.00      1.00         7
```

---

## **License**
This project is licensed under the MIT License.

---
