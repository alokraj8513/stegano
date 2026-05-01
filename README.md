🛡️ Advanced Cryptographic Steganography & Forensic Suite

A dual-purpose security platform built in Python. This suite functions as a highly secure data-hiding utility utilizing modern authenticated cryptography, while concurrently acting as a forensic analysis tool capable of detecting hidden payloads via bit-plane visualization and statistical anomaly heuristics.

✨ Key Features

Cryptographic Engine: Secures payloads before embedding using industry-standard algorithms, ensuring data confidentiality and integrity.

AES-256-GCM: Authenticated encryption (protects against tampering).

ChaCha20-Poly1305: High-speed, highly secure stream cipher.

Fernet: Standard Python secure recipe (AES-128-CBC + HMAC-SHA256).

XOR (Legacy): Educational baseline for forensic comparison.

Steganography Engine: Employs Least Significant Bit (LSB) substitution to embed encrypted payloads seamlessly into image channels without visual distortion.

Forensic Analysis Suite: Simulates digital forensics to detect anomalous data.

Data Concentration Map: Generates a high-contrast visual map of the 0th bit-plane, immediately exposing sequentially embedded steganography.

Statistical Steganalysis: A localized density heuristic that detects unnatural variance in LSB distribution, flagging modified images without requiring the decryption key.

Modern GUI: A fully featured, dark-mode graphical interface built with customtkinter for streamlined encryption, decryption, and forensic analysis workflows.

🛠️ Tech Stack

Language: Python 3

Computer Vision / Matrices: cv2 (OpenCV), numpy

Security: cryptography

Interface: customtkinter, tkinter

🚀 Installation & Setup

Clone the repository:

git clone repo-name
cd steganography-suite


Create a virtual environment (Recommended):

python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate


Install dependencies:

pip install opencv-python numpy cryptography customtkinter


Run the application:

python app.py


📘 How to Use

🔐 Encryption

Navigate to the Encryption tab.

Select a carrier image (PNG is highly recommended to prevent lossy compression from destroying the payload).

Select an encryption algorithm (AES-256-GCM recommended).

Enter your secret message and a strong password.

Click Embed Message. A new _encoded image will be saved to your directory.

🔓 Decryption

Navigate to the Decryption tab.

Select the encoded image.

Select the exact same algorithm and enter the exact same password used during encryption.

Click Extract Message to retrieve the payload.

🕵️ Forensic Analysis

Navigate to the Forensic Analysis tab.

Select an image to investigate.

Click Generate Data Concentration Map to slice the LSB plane and visually identify hidden data blocks.

Click Run ML Steganalysis to run the statistical heuristic engine and determine the probability of steganographic modification.

🧠 Technical Architecture

Defense-in-Depth

This application avoids "security by obscurity." Even if an adversary knows the exact LSB extraction algorithm and extracts the payload, they are met with high-entropy ciphertext. Without the PBKDF2-derived key and the correct initialization vector/nonce, the message remains cryptographically secure. Furthermore, the GCM and Poly1305 modes ensure that any attempt to alter the image bits will result in an immediate decryption failure, alerting the user to tampering.

Forensic Visualizer

Standard images exhibit natural, smooth noise in their least significant bits. Encrypted data, however, is statistically indistinguishable from pure, high-density random noise. By isolating the img & 1 bit-plane and amplifying it, the visualizer forces this hidden high-density noise to contrast sharply against natural image patterns, allowing human analysts to instantly spot sequential embedding.

⚠️ Disclaimer

This tool is developed strictly for educational purposes, portfolio demonstration, and digital forensics research. The author is not responsible for any misuse of this software.

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.