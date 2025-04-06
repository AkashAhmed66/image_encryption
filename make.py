import os
import json
import random
import numpy as np
from PIL import Image
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Define input and output directories here
INPUT_DIR = "input_images"
OUTPUT_DIR = "output_json"

def get_encryption_key(password):
    """
    Generate a Fernet encryption key from password
    """
    password_bytes = password.encode()
    salt = b'anthropicsalt123'  # In production, you'd want to generate and store a unique salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def encrypt_data(data, password):
    """
    Encrypt data using the password
    """
    key = get_encryption_key(password)
    fernet = Fernet(key)
    data_bytes = json.dumps(data).encode()
    encrypted_data = fernet.encrypt(data_bytes)
    return base64.b64encode(encrypted_data).decode()

def process_rgb_images(password):
    """
    Process all RGB images in the input directory:
    1. Add random numbers to each channel (RGB) of each pixel
    2. Encrypt the processing details using the password
    3. Save processed image as JSON in output_dir
    4. Save encrypted random values as JSON in output_dir
    """
    # Create output directory if it doesn't exist
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
   
    # Process each file in the input directory
    for filename in os.listdir(INPUT_DIR):
        file_path = os.path.join(INPUT_DIR, filename)
       
        # Skip directories and non-image files
        if os.path.isdir(file_path) or not is_image_file(filename):
            continue
       
        try:
            # Open image and ensure it's RGB
            img = Image.open(file_path)
            if img.mode != 'RGB':
                print(f"Skipping {filename}: Not an RGB image")
                continue
           
            # Convert image to numpy array for processing
            img_array = np.array(img)
            height, width, channels = img_array.shape
           
            # Generate random numbers for each pixel and channel
            random_values = np.zeros((height, width, channels), dtype=np.int32)
            processed_img = np.zeros((height, width, channels), dtype=np.int32)
           
            # For each pixel and channel, add a random number that doesn't exceed 255
            for h in range(height):
                for w in range(width):
                    for c in range(channels):
                        # Get current pixel value
                        current_value = int(img_array[h, w, c])
                       
                        random_val = random.randint(256, 999)
                       
                        # These are the lines we want to encrypt with the password
                        random_values[h, w, c] = current_value + random_val
                        processed_img[h, w, c] = random_val
           
            # Get base name for output files
            base_name = os.path.splitext(filename)[0]
           
            # Save processed image as JSON (encrypted)
            processed_json_path = os.path.join(OUTPUT_DIR, f"{base_name}.json")
            encrypted_processed = encrypt_data(processed_img.tolist(), password)
            with open(processed_json_path, 'w') as f:
                f.write(encrypted_processed)
           
            # Save random values as JSON (encrypted)
            random_json_path = os.path.join(OUTPUT_DIR, f"{base_name}a.json")
            encrypted_random = encrypt_data(random_values.tolist(), password)
            with open(random_json_path, 'w') as f:
                f.write(encrypted_random)
           
            print(f"Processed and encrypted {filename}")
           
        except Exception as e:
            print(f"Error processing {filename}: {e}")

def is_image_file(filename):
    """Check if a file is likely to be an image based on extension"""
    image_extensions = ['.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.gif']
    return any(filename.lower().endswith(ext) for ext in image_extensions)

# Execute the script
if __name__ == "__main__":
    print(f"Starting secure image processing from {INPUT_DIR} to {OUTPUT_DIR}")
    password = input("Enter encryption password: ")
    process_rgb_images(password)
    print(f"Processing complete. Encrypted images and random values saved to {OUTPUT_DIR}")