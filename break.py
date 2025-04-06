import os
import json
import numpy as np
from PIL import Image
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Define input and output directories
INPUT_JSON_DIR = "output_json"
VIEW_DIR = "view_images"

def get_encryption_key(password):
    """
    Generate a Fernet encryption key from password
    """
    password_bytes = password.encode()
    salt = b'anthropicsalt123'  # Must match the salt used in make.py
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def decrypt_data(encrypted_data, password):
    """
    Decrypt data using the password
    """
    try:
        key = get_encryption_key(password)
        fernet = Fernet(key)
        data_bytes = base64.b64decode(encrypted_data)
        decrypted_data = fernet.decrypt(data_bytes)
        return json.loads(decrypted_data)
    except Exception as e:
        print(f"Decryption error: {e}")
        print("This could be due to an incorrect password.")
        return None

def regenerate_images(password):
    """
    Regenerate images from pairs of encrypted JSON files:
    1. Read and decrypt processed image JSON and random values JSON
    2. Subtract random values from processed image to get original
    3. Save reconstructed image to view directory
    """
    # Create view directory if it doesn't exist
    if not os.path.exists(VIEW_DIR):
        os.makedirs(VIEW_DIR)
   
    # Get all JSON files in the input directory
    all_files = os.listdir(INPUT_JSON_DIR)
    processed_files = [f for f in all_files if not f.endswith('a.json')]
   
    for processed_filename in processed_files:
        try:
            # Get base name and construct paths
            base_name = os.path.splitext(processed_filename)[0]
            processed_path = os.path.join(INPUT_JSON_DIR, processed_filename)
            random_path = os.path.join(INPUT_JSON_DIR, f"{base_name}a.json")
           
            # Check if both files exist
            if not os.path.exists(random_path):
                print(f"Skipping {processed_filename}: Missing random values file")
                continue
           
            # Load encrypted JSON data
            with open(processed_path, 'r') as f:
                encrypted_processed = f.read()
           
            with open(random_path, 'r') as f:
                encrypted_random = f.read()
           
            # Decrypt data
            processed_data = decrypt_data(encrypted_processed, password)
            random_data = decrypt_data(encrypted_random, password)
            
            if processed_data is None or random_data is None:
                print(f"Skipping {processed_filename}: Decryption failed")
                continue
           
            # Convert to numpy arrays
            processed_array = np.array(processed_data, dtype=np.int32)
            random_array = np.array(random_data, dtype=np.int32)
           
            # Reconstruct original image by subtracting random values
            original_array = np.array(random_array - processed_array, dtype=np.uint8)
           
            # Create PIL image from numpy array
            reconstructed_img = Image.fromarray(original_array)
           
            # Save reconstructed image
            output_path = os.path.join(VIEW_DIR, f"{base_name}.png")
            reconstructed_img.save(output_path)
           
            print(f"Reconstructed {base_name}.png")
           
        except Exception as e:
            print(f"Error reconstructing {processed_filename}: {e}")

if __name__ == "__main__":
    print(f"Starting secure image reconstruction from {INPUT_JSON_DIR} to {VIEW_DIR}")
    password = input("Enter decryption password: ")
    regenerate_images(password)
    print(f"Reconstruction complete. Original images saved to {VIEW_DIR}")