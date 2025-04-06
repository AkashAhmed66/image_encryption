import os
import json
import numpy as np
from PIL import Image

# Define input and output directories
INPUT_JSON_DIR = "output_json"
VIEW_DIR = "view_images"

def regenerate_images():
    """
    Regenerate images from pairs of JSON files:
    1. Read processed image JSON and random values JSON
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
            
            # Load JSON data
            with open(processed_path, 'r') as f:
                processed_data = json.load(f)
            
            with open(random_path, 'r') as f:
                random_data = json.load(f)
            
            # Convert to numpy arrays
            processed_array = np.array(processed_data, dtype=np.uint8)
            random_array = np.array(random_data, dtype=np.uint8)
            
            # Reconstruct original image by subtracting random values
            original_array = processed_array - random_array
            
            # Create PIL image from numpy array
            reconstructed_img = Image.fromarray(original_array)
            
            # Save reconstructed image
            output_path = os.path.join(VIEW_DIR, f"{base_name}.png")
            reconstructed_img.save(output_path)
            
            print(f"Reconstructed {base_name}.png")
            
        except Exception as e:
            print(f"Error reconstructing {processed_filename}: {e}")

if __name__ == "__main__":
    print(f"Starting image reconstruction from {INPUT_JSON_DIR} to {VIEW_DIR}")
    regenerate_images()
    print(f"Reconstruction complete. Original images saved to {VIEW_DIR}")