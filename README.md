Network Traffic Analyzer (ML-Powered IDS Proof-of-Concept)

🛡️ Project Overview

This project is a proof-of-concept for a Machine Learning-powered Intrusion Detection System (IDS) that analyzes network packets in real-time or from PCAP files.

It leverages Python, Scapy, and Flask to perform real-time feature extraction and uses a pre-trained multi-classification model to identify various types of network anomalies and attacks (e.g., DoS, PortScan, Normal traffic). The results are visualized on a modern, responsive web interface built with pure HTML/Tailwind CSS.

✨ Key Features

Real-time Multi-Classification: Capable of capturing live network traffic, extracting flow-based features, and classifying traffic into multiple categories (e.g., Normal, DoS, Probe).

Packet Capture & Analysis: Uses the Scapy library to parse raw packets and extract required flow metrics.

RESTful API Backend: Built with Flask to expose two primary configurable endpoints for:

GET /live_predict: Initiates a network capture for a specified duration.

POST /upload: Handles the upload and analysis of PCAP (.pcap/.pcapng) files.

Interactive Frontend: A single-page HTML application using Chart.js and Tailwind CSS to display traffic distribution (Normal vs. Malicious) via dynamic doughnut charts.

Robust Structure: Follows a modular design suitable for deployment in monitoring environments.

🚀 Getting Started

Prerequisites

Python 3.x

Pip (Python package installer)

Wireshark/TShark (optional)

Installation

Clone the repository and install the required Python packages:

git clone [https://github.com/Takura-Z/NetworkTrafficAnalyzer.git](https://github.com/Takura-Z/NetworkTrafficAnalyzer.git)
cd NetworkTrafficAnalyzer
pip install -r requirements.txt


(Note: A requirements.txt listing Flask, scapy, pandas, joblib, and numpy is assumed.)

⚠️ IMPORTANT: Model File Exclusion

The trained Machine Learning model (traffic_analyzer_model.joblib) is approximately 103 MB and exceeds GitHub's file size limit, therefore it is excluded from this repository and listed in .gitignore.

For the application to run successfully, you need to provide three placeholder files (even if they are empty) in the root directory.

Create the following three files in the main project directory:

touch traffic_analyzer_model.joblib
touch scaler.joblib
touch label_encoder.joblib


(The app.py script contains simulation logic that handles missing model files, allowing the application to run immediately for demonstration.)

⚙️ How to Run the Application

This project requires two separate components to be running: the Flask Backend and the Frontend Interface.

1. Start the Flask Backend

Run the main Python application. This will start the API server on http://0.0.0.0:5000.

python new_backend.py


(Note: Running the live capture endpoint (/live_predict) may require administrator permissions (e.g., sudo or "Run as Administrator") on some systems to access network interfaces via Scapy.)

2. Launch the Frontend

Open the index.html file in your web browser. This single-page application is fully responsive and will automatically attempt to connect to the Flask API.

You can now:

Test Live Capture: Enter a duration (e.g., 10 seconds) and click "Start Live Capture." The backend will simulate capturing and classifying real-time traffic.

Test PCAP Upload: Upload a sample PCAP file. which you can upload and analyze 



🛠 Project Structure

NetworkTrafficAnalyzer/
├── new_backend.py                      # Flask backend, Scapy integration, and ML prediction API.
├── index.html                  # Frontend interface (HTML, CSS/Tailwind, JS/Chart.js).
├── README.md                   # This file.
└── .gitignore                  # Explicitly excludes the large ML model files.


💻 Technologies Used

Python 3.x

Flask (Web Framework/API)

Scapy (Packet Manipulation and Feature Extraction)

Pandas / Joblib (Data Handling and Model Persistence)

HTML5 / Tailwind CSS (Responsive Frontend Styling)

Chart.js (Data Visualization)
