#generating dummy api
import random
import csv
from datetime import datetime, timedelta

def generate_sample_traffic(num_rows=100):
    ip_range = ["192.168.1.{}".format(i) for i in range(1, 7)]
    protocols = [6, 17]  # TCP (6), UDP (17)
    labels = [0, 1]  # 0 = normal, 1 = intrusion
    data = []

    start_time = datetime.now()

    for _ in range(num_rows):
        src_ip = random.choice(ip_range)
        dst_ip = random.choice(ip_range)
        protocol = random.choice(protocols)
        length = random.randint(64, 1500)  
        timestamp = start_time.strftime('%Y-%m-%d %H:%M:%S')
        label = random.choice(labels)
        data.append([src_ip, dst_ip, protocol, length, timestamp, label])
        start_time += timedelta(seconds=1)

    return data

def write_to_csv(filename, data):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['src_ip', 'dst_ip', 'protocol', 'length', 'timestamp', 'label'])  
        writer.writerows(data)

data = generate_sample_traffic(100)
write_to_csv('traffic_data.csv', data)
print("CSV file 'traffic_data.csv' created.")
