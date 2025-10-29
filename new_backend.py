import os
import io
import pandas as pd
import joblib
import numpy as np
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from scapy.all import sniff, IP, TCP, UDP
from werkzeug.utils import secure_filename

# --- Configuration ---
app = Flask(__name__)
# Enable CORS for all domains, crucial for front-end/back-end communication
CORS(app) 
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pcap', 'pcapng'}

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Load the trained model, scaler, and label encoder
try:
    # UPDATING FILE NAMES to match user's expected names (.joblib)
    MODEL_PATH = 'traffic_analyzer_model.joblib'
    SCALER_PATH = 'scaler.joblib'
    LABEL_ENCODER_PATH = 'label_encoder.joblib' 
    
    # Check if the files exist before loading
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH) or not os.path.exists(LABEL_ENCODER_PATH):
        raise FileNotFoundError(f"One or more required files not found. Check for: {MODEL_PATH}, {SCALER_PATH}, and {LABEL_ENCODER_PATH}.")

    # We use joblib.load for .joblib files
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    # Load the label encoder
    label_encoder = joblib.load(LABEL_ENCODER_PATH)
    
    # NOTE: FINAL CORRECTED LIST of 78 features. 
    # The four features that caused the error (Init Fwd Win Bytes, etc.) have been corrected 
    # to match the model's expected snake_case naming (Init_Win_bytes_forward, etc.).
    MODEL_FEATURES = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 
        'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 
        'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 
        'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 
        'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 
        'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 
        'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 
        'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 
        'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 
        'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 
        'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 
        'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk', 
        'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 
        'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 
        'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 
        'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 
        'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ]


    print("Model, scaler, and label encoder loaded successfully.")

except Exception as e:
    print(f"Error loading model, scaler, or encoder: {e}")
    model = None
    scaler = None
    label_encoder = None # Initialize to None if loading fails
    MODEL_FEATURES = []
# --- Feature Extraction and Prediction Logic ---

def extract_flow_features(packets):
    """
    Simulates extracting basic features from a list of Scapy packets to create a DataFrame.
    
    The function initializes ALL 78 required features to 0 to prevent the model from failing 
    due to missing columns, which is the necessary compromise since we cannot fully
    replicate a complex flow analysis tool (like CicFlowMeter) with Scapy alone.
    """
    if not packets:
        return pd.DataFrame(columns=MODEL_FEATURES)

    data = []
    
    # Create a base set of features, initializing all 78 required features to 0.
    base_features = {feature: 0.0 for feature in MODEL_FEATURES}

    for pkt in packets:
        # We only process IP packets for flow features
        if IP in pkt:
            ip_layer = pkt[IP]
            transport_layer = pkt.getlayer(TCP) or pkt.getlayer(UDP)
            
            # Start with the base features
            features = base_features.copy()
            
            # OVERWRITE the few features we can approximate from a single packet
            features['Destination Port'] = transport_layer.dport if transport_layer else 0
            features['Total Fwd Packets'] = 1
            features['Total Backward Packets'] = 0
            features['Total Length of Fwd Packets'] = len(pkt)
            features['Total Length of Bwd Packets'] = 0
            features['Fwd Packet Length Max'] = len(pkt)
            features['Fwd Packet Length Mean'] = len(pkt)
            features['Min Packet Length'] = len(pkt)
            features['Max Packet Length'] = len(pkt)
            features['Packet Length Mean'] = len(pkt)
            features['Subflow Fwd Packets'] = 1
            features['Subflow Fwd Bytes'] = len(pkt)
            
            # Flag Counts (only if TCP is present)
            if TCP in pkt:
                features['ACK Flag Count'] = 1 if 'A' in pkt[TCP].flags else 0
                features['SYN Flag Count'] = 1 if 'S' in pkt[TCP].flags else 0
                features['FIN Flag Count'] = 1 if 'F' in pkt[TCP].flags else 0
                features['RST Flag Count'] = 1 if 'R' in pkt[TCP].flags else 0
                features['PSH Flag Count'] = 1 if 'P' in pkt[TCP].flags else 0
                features['URG Flag Count'] = 1 if 'U' in pkt[TCP].flags else 0
                
                # Approximation for Init Window Bytes (using correct name: Init_Win_bytes_forward)
                features['Init_Win_bytes_forward'] = pkt[TCP].window
                # Approximation for Fwd Active Data Pkts (using correct name: act_data_pkt_fwd)
                features['act_data_pkt_fwd'] = 1
                # Approximation for Min Segment Size (using correct name: min_seg_size_forward)
                features['min_seg_size_forward'] = len(pkt)


            # Simple adjustments for Bwd Pkts
            if transport_layer and transport_layer.dport < transport_layer.sport:
                features['Total Fwd Packets'] = 0
                features['Total Backward Packets'] = 1
                features['Total Length of Fwd Packets'] = 0
                features['Total Length of Bwd Packets'] = len(pkt)
                features['Subflow Fwd Packets'] = 0
                features['Subflow Fwd Bytes'] = 0
                features['Subflow Bwd Packets'] = 1
                features['Subflow Bwd Bytes'] = len(pkt)
                
                # If we assume this is a reverse packet, approximate Bwd features
                features['Fwd Packet Length Max'] = 0
                features['Fwd Packet Length Mean'] = 0
                features['Bwd Packet Length Max'] = len(pkt)
                features['Bwd Packet Length Mean'] = len(pkt)
                
                if TCP in pkt:
                     # Approximation for Init Window Bytes (using correct name: Init_Win_bytes_backward)
                     features['Init_Win_bytes_backward'] = pkt[TCP].window


            data.append(features)

    # Convert to DataFrame, ensuring all required columns exist and are ordered correctly
    df = pd.DataFrame(data)
    # Fill any remaining missing columns (which shouldn't happen with our base_features dict, but good safety check)
    for feature in MODEL_FEATURES:
        if feature not in df.columns:
            df[feature] = 0
            
    # Select and reorder columns to match the model's expected input
    return df[MODEL_FEATURES]

def predict_traffic_type(df):
    """
    Scales the feature DataFrame, makes predictions, and decodes the labels.
    Returns a dictionary of human-readable classification counts.
    """
    if df.empty:
        return {}
    
    # 1. Scale the features
    scaled_features = scaler.transform(df)
    
    # 2. Make numeric predictions
    numeric_predictions = model.predict(scaled_features)
    
    # 3. Decode predictions back to string labels using the loaded Label Encoder
    string_predictions = label_encoder.inverse_transform(numeric_predictions)
    
    # 4. Count classifications (now using string labels)
    unique, counts = np.unique(string_predictions, return_counts=True)
    
    # FIX: Convert NumPy int64 counts to standard Python int for JSON serialization
    classification_counts = {str(k): int(v) for k, v in zip(unique, counts)}
    
    return classification_counts

# --- Helper Functions ---
def allowed_file(filename):
    """Checks if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- Flask Routes ---

@app.route('/', methods=['GET'])
def check_status():
    """Simple status check route."""
    # Check status of all three components
    all_loaded = model is not None and scaler is not None and label_encoder is not None
    return jsonify({"status": "healthy", "model_loaded": all_loaded})


@app.route('/upload', methods=['POST'])
def upload_pcap():
    """Handles PCAP file upload and analysis."""
    # Check if all required components are loaded
    if not all([model, scaler, label_encoder]):
        return jsonify({"error": "Analysis pipeline is incomplete (Model, Scaler, or Encoder missing). Cannot perform analysis."}), 503

    if 'pcap_file' not in request.files:
        return jsonify({"error": "No file part in the request."}), 400
    
    file = request.files['pcap_file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file."}), 400
        
    if file and allowed_file(file.filename):
        try:
            # Read file content into a buffer
            pcap_bytes = file.read()
            # Use Scapy's rdpcap to read packets from the raw bytes (io.BytesIO is needed)
            packets = sniff(offline=io.BytesIO(pcap_bytes), store=1)
            
            if not packets:
                return jsonify({"error": "The uploaded file contains no readable packets."}), 400

            # 1. Extract features
            features_df = extract_flow_features(packets)
            
            # 2. Make predictions
            results = predict_traffic_type(features_df)
            
            return jsonify(results)
        
        except Exception as e:
            # Catch exceptions during processing
            print(f"Error during PCAP analysis: {e}")
            return jsonify({"error": f"Error processing PCAP file: {str(e)}"}), 500

    return jsonify({"error": "Invalid file type. Only .pcap or .pcapng files are allowed."}), 400


@app.route('/live_predict', methods=['GET'])
def live_predict():
    """
    Performs a live network capture for a specified duration and analyzes the traffic.
    """
    # Check if all required components are loaded
    if not all([model, scaler, label_encoder]):
        return jsonify({"error": "Analysis pipeline is incomplete (Model, Scaler, or Encoder missing). Cannot perform live analysis."}), 503

    try:
        # Get the duration from the query string (e.g., /live_predict?duration=20)
        # Safely casts to integer, defaults to 10 if missing or invalid
        capture_duration = request.args.get('duration', default=10, type=int)
        
        # Simple validation check (should mirror frontend validation)
        if capture_duration < 5 or capture_duration > 86400:
            return jsonify({"error": "Invalid capture duration. Must be between 5 and 86400 seconds."}), 400
            
        print(f"Starting live capture for {capture_duration} seconds...")
        
        # Use Scapy's sniff function with the configurable timeout
        packets = sniff(timeout=capture_duration, store=1)
        
        print(f"Capture finished. Captured {len(packets)} packets.")

        if not packets:
            return jsonify({"error": "No packets were captured during the specified time."}), 400

        # 1. Extract features
        features_df = extract_flow_features(packets)
        
        # 2. Make predictions
        results = predict_traffic_type(features_df)
        
        return jsonify(results)
    
    except Exception as e:
        print(f"Error during live capture: {e}")
        return jsonify({"error": f"Error during live capture/analysis: {str(e)}. (Hint: Check network interface permissions and configuration.)"}), 500


if __name__ == '__main__':
    #  Running on 0.0.0.0 makes it accessible outside the container/local machine
    app.run(debug=True, host='0.0.0.0', port=5000)
