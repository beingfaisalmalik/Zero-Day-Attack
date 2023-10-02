import psutil
import tkinter as tk
from tkinter import messagebox
import time
import numpy as np
import pandas as pd
import warnings
import matplotlib.pyplot as plt
import seaborn as sns
import tensorflow as tf
import warnings
from tensorflow.keras.layers import Input, Dense  
from tensorflow.keras.models import Model 
from sklearn.exceptions import NotFittedError
from tensorflow.keras import regularizers
import xgboost as xgb
from sklearn.decomposition import PCA
from scapy.all import *
import time
import random
import threading
from sklearn import tree
from sklearn.naive_bayes import GaussianNB
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn import metrics
pd.set_option('display.max_columns',None)
warnings.filterwarnings('ignore')





def show_warning(s):
    root = tk.Tk()
    root.withdraw() 
    messagebox.showwarning(f"{s}")
def show(s):
    root = tk.Tk()
    root.withdraw()  
   
    messagebox.showinfo(f"{s}")
    root.withdraw()
    
data_train =pd.read_csv('KDDTrain+.txt')

columns = (['duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment','urgent','hot'
,'num_failed_logins','logged_in','num_compromised','root_shell','su_attempted','num_root','num_file_creations'
,'num_shells','num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count','srv_count','serror_rate'
,'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count'
,'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate'
,'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate','outcome','level'])

data_train.columns = columns
data_train.loc[data_train['outcome'] == "normal", "outcome"] = 'normal'
data_train.loc[data_train['outcome'] != 'normal', "outcome"] = 'attack'

def Scaling(df_num, cols):
    std_scaler = RobustScaler()
    std_scaler_temp = std_scaler.fit_transform(df_num)
    std_df = pd.DataFrame(std_scaler_temp, columns =cols)
    return std_df

cat_cols = ['is_host_login','protocol_type','service','flag','land', 'logged_in','is_guest_login', 'level', 'outcome']
def preprocess(dataframe):
    df_num = dataframe.drop(cat_cols, axis=1)
    num_cols = df_num.columns
    scaled_df = Scaling(df_num, num_cols)

    dataframe.drop(labels=num_cols, axis="columns", inplace=True)
    dataframe[num_cols] = scaled_df[num_cols]

    dataframe.loc[dataframe['outcome'] == "normal", "outcome"] = 0
    dataframe.loc[dataframe['outcome'] != 0, "outcome"] = 1

    dataframe = pd.get_dummies(dataframe, columns = ['protocol_type', 'service', 'flag'])
    return dataframe
scaled_train = preprocess(data_train)
column_names_list = scaled_train.columns.tolist()
x = scaled_train.drop(['outcome', 'level'] , axis = 1).values

y = scaled_train['outcome'].values
y_reg = scaled_train['level'].values

pca = PCA(n_components=30)
pca = pca.fit(x)
x_reduced = pca.transform(x)


y = y.astype('int')
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=42)
x_train_reduced, x_test_reduced, y_train_reduced, y_test_reduced = train_test_split(x_reduced, y, test_size=0.3, random_state=42)
x_train_reg, x_test_reg, y_train_reg, y_test_reg = train_test_split(x, y_reg, test_size=0.2, random_state=42)

kernal_evals = dict()
from sklearn.metrics import ConfusionMatrixDisplay
def evaluate_classification(model, name, X_train, X_test, y_train, y_test):
    train_accuracy = metrics.accuracy_score(y_train, model.predict(X_train))
    test_accuracy = metrics.accuracy_score(y_test, model.predict(X_test))
    
    train_precision = metrics.precision_score(y_train, model.predict(X_train))
    test_precision = metrics.precision_score(y_test, model.predict(X_test))
    
    train_recall = metrics.recall_score(y_train, model.predict(X_train))
    test_recall = metrics.recall_score(y_test, model.predict(X_test))
    
    train_f1 = metrics.f1_score(y_train, model.predict(X_train))
    test_f1 = metrics.f1_score(y_test, model.predict(X_test))
    
    kernal_evals[str(name)] = [train_accuracy, test_accuracy, train_precision, test_precision, train_recall, test_recall, train_f1, test_f1]
    
    print("Training Accuracy " + str(name) + ": {:.2f}%".format(train_accuracy*100))
    print("Test Accuracy " + str(name) + ": {:.2f}%".format(test_accuracy*100))
    print("Training Precision " + str(name) + ": {:.2f}%".format(train_precision*100))
    print("Test Precision " + str(name) + ": {:.2f}%".format(test_precision*100))
    print("Training Recall " + str(name) + ": {:.2f}%".format(train_recall*100))
    print("Test Recall " + str(name) + ": {:.2f}%".format(test_recall*100))
    print("Training F1-Score " + str(name) + ": {:.2f}%".format(train_f1*100))
    print("Test F1-Score " + str(name) + ": {:.2f}%".format(test_f1*100))
    





while True:
    input_data = {'land': 1, 'logged_in': 0, 'is_host_login': 1, 'is_guest_login': 0, 'duration': 1, 'src_bytes': 0, 'dst_bytes': 0, 'wrong_fragment': 0,
                'urgent': 0, 'hot': 1, 'num_failed_logins': 0, 'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0, 'num_root': 1, 'num_file_creations': 1, 
                'num_shells': 1, 'num_access_files': 1, 'num_outbound_cmds': 0, 'count': 1, 'srv_count': 1, 'serror_rate': 0, 'srv_serror_rate': 0, 'rerror_rate': 1, 
                'srv_rerror_rate': 0, 'same_srv_rate': 1, 'diff_srv_rate': 1, 'srv_diff_host_rate': 0, 'dst_host_count': 0, 'dst_host_srv_count': 0, 'dst_host_same_srv_rate': 1, 
                'dst_host_diff_srv_rate': 0, 'dst_host_same_src_port_rate': 0, 'dst_host_srv_diff_host_rate': 0, 'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 1, 
                'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 1, 'protocol_type_icmp': 0, 'protocol_type_tcp': 1, 'protocol_type_udp': 1, 'service_IRC': 1,
                'service_X11': 0, 'service_Z39_50': 0, 'service_aol': 1, 'service_auth': 1, 'service_bgp': 0, 'service_courier': 1, 'service_csnet_ns': 0, 'service_ctf': 0, 
                'service_daytime': 1, 'service_discard': 1, 'service_domain': 0, 'service_domain_u': 1, 'service_echo': 1, 'service_eco_i': 0, 'service_ecr_i': 0, 
                'service_efs': 1, 'service_exec': 1, 'service_finger': 1, 'service_ftp': 1, 'service_ftp_data': 0, 'service_gopher': 1, 'service_harvest': 0, 'service_hostnames': 1, 
                'service_http': 1, 'service_http_2784': 1, 'service_http_443': 0, 'service_http_8001': 1, 'service_imap4': 0, 'service_iso_tsap': 1, 'service_klogin': 1, 
                'service_kshell': 0, 'service_ldap': 0, 'service_link': 1, 'service_login': 0, 'service_mtp': 1, 'service_name': 1, 'service_netbios_dgm': 1, 'service_netbios_ns': 1,
                'service_netbios_ssn': 1, 'service_netstat': 1, 'service_nnsp': 1, 'service_nntp': 1, 'service_ntp_u': 0, 'service_other': 1, 'service_pm_dump': 1, 
                'service_pop_2': 0, 'service_pop_3': 1, 'service_printer': 0, 'service_private': 0, 'service_red_i': 1, 'service_remote_job': 1, 'service_rje': 1, 
                'service_shell': 1, 'service_smtp': 0, 'service_sql_net': 0, 'service_ssh': 1, 'service_sunrpc': 1, 'service_supdup': 0, 'service_systat': 0, 'service_telnet': 1, 
                'service_tftp_u': 1, 'service_tim_i': 1, 'service_time': 0, 'service_urh_i': 0, 'service_urp_i': 1, 'service_uucp': 0, 'service_uucp_path': 1, 'service_vmnet': 1, 
                'service_whois': 0, 'flag_OTH': 1, 
                'flag_REJ': 1, 'flag_RSTO': 0, 'flag_RSTOS0': 1, 'flag_RSTR': 0, 'flag_S0': 1, 'flag_S1': 1, 'flag_S2': 0, 'flag_S3': 1, 'flag_SF': 0, 'flag_SH': 1}
    l = [0,1]
    extracted_values_dict = {}
    lock = threading.Lock()

    def extract_values(packet, column_names):
        extracted_values = {}
        for column in column_names:
            if column in packet:
                value = packet[column]
                extracted_values[column] = value
            else:
                extracted_values[column] = random.choice(l)
        return extracted_values


    def packet_callback(packet, column_names):
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                seq_number = packet[TCP].seq
                ack_number = packet[TCP].ack
                window_size = packet[TCP].window

                print(f"Source Port: {src_port}, Destination Port: {dst_port}, Flags: {flags}")
                print(f"Sequence Number: {seq_number}, Acknowledgment Number: {ack_number}")
                print(f"Window Size: {window_size}")

            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                length = len(packet[UDP])

                print(f"Source Port: {src_port}, Destination Port: {dst_port}, Length: {length}")

            if ICMP in packet:
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code

                print(f"ICMP Type: {icmp_type}, ICMP Code: {icmp_code}")

            
            global extracted_values_dict
            with lock:
                extracted_values = extract_values(packet, column_names)
                extracted_values_dict = extracted_values 


    def capture_packets(interface, column_names):
        sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, column_names), store=0)

    interface = "Wi-Fi"  
    column_names = ['land', 'logged_in', 'is_host_login', 'level', 'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'protocol_type_icmp', 'protocol_type_tcp', 'protocol_type_udp', 'service_IRC', 'service_X11', 'service_Z39_50', 'service_aol', 'service_auth', 'service_bgp', 'service_courier', 'service_csnet_ns', 'service_ctf', 'service_daytime', 'service_discard', 'service_domain', 'service_domain_u', 'service_echo', 'service_eco_i', 'service_ecr_i', 'service_efs', 'service_exec', 'service_finger', 'service_ftp', 'service_ftp_data', 'service_gopher', 'service_harvest', 'service_hostnames', 'service_http', 'service_http_2784', 'service_http_443', 'service_http_8001', 'service_imap4', 'service_iso_tsap', 'service_klogin', 'service_kshell', 'service_ldap', 'service_link', 'service_login', 'service_mtp', 'service_name', 'service_netbios_dgm', 'service_netbios_ns', 'service_netbios_ssn', 'service_netstat', 'service_nnsp', 'service_nntp', 'service_ntp_u', 'service_other', 'service_pm_dump', 'service_pop_2', 'service_pop_3', 'service_printer', 'service_private', 'service_red_i', 'service_remote_job', 'service_rje', 'service_shell', 'service_smtp', 'service_sql_net', 'service_ssh', 'service_sunrpc', 'service_supdup', 'service_systat', 'service_telnet', 'service_tftp_u', 'service_tim_i', 'service_time', 'service_urh_i', 'service_urp_i', 'service_uucp', 'service_uucp_path', 'service_vmnet', 'service_whois', 'flag_OTH', 'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR', 'flag_S0', 'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH'] # Your list of column names

    

    packet_capture_thread = threading.Thread(target=lambda: sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, column_names), count=1, store=0))
    packet_capture_thread.start()

        
    time.sleep(10)  

       
    with lock:
        if bool(extracted_values_dict):
            print(f"Recieved Packet Values: {extracted_values_dict}")
        else:
            extracted_values_dict = input_data
            print(f"Recieved Packet Values: {extracted_values_dict}")
            
        
    time.sleep(5)
    input_list2 = []
    for value in extracted_values_dict.values():
        input_list2.append(value)
    input_list2 = np.array(input_list2)

    x_train = x_train.astype(np.float32)
    x_test = x_test.astype(np.float32)

    
    input_dim = x_train.shape[1]
    encoding_dim = 15

    input_layer = Input(shape=(input_dim,))
    encoder = Dense(encoding_dim, activation="relu")(input_layer)
    decoder = Dense(input_dim, activation="sigmoid")(encoder)
    autoencoder = Model(inputs=input_layer, outputs=decoder)

    autoencoder.compile(optimizer='adam', loss='mean_squared_error')

    autoencoder.fit(x_train, x_train, epochs=5, batch_size=32, shuffle=True, validation_data=(x_test, x_test))

    
    encoder_model = Model(inputs=input_layer, outputs=encoder)

    
    encoded_x_train = encoder_model.predict(x_train)
    encoded_x_test = encoder_model.predict(x_test)

   
    models = {
        'Logistic Regression': LogisticRegression(),
        'Decision Tree': DecisionTreeClassifier(),
        ' XGB Classifier': xgb.XGBClassifier(objective='binary:logistic', n_estimators=100, random_state=50),
    }

    for model_name, model in models.items():
        print(f"Training and evaluating {model_name}")
        model.fit(encoded_x_train, y_train)
        

    xgb_classifier = xgb.XGBClassifier(objective='binary:logistic', n_estimators=50, random_state=50)
    xgb_classifier.fit(encoded_x_train, y_train)

    
    input_example = input_list2  
    encoded_input = encoder_model.predict(np.array([input_example])) 

   
    predicted_outcome = xgb_classifier.predict(encoded_input)
   
    if predicted_outcome[0] == 0:
        s = "Predicted Outcome: Normal"
        print(f"{s}")
        show(s)
    else:
        s = "Predicted Outcome: Attack"
        print(f"{s}")
        show_warning(s)
        
        
    
    
    time.sleep(10)
