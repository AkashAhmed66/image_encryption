import os
import json
import random
import numpy as np
from PIL import Image

# Define input and output directories here
INPUT_DIR = "input_images"
OUTPUT_DIR = "output_json"

def process_rgb_images():
    """
    Process all RGB images in the input directory:
    1. Add random numbers to each channel (RGB) of each pixel
    2. Save processed image as JSON in output_dir
    3. Save random numbers used as JSON in output_dir
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
                        
                        random_values[h, w, c] = current_value + random_val
                        processed_img[h, w, c] = random_val
           
            # Get base name for output files
            base_name = os.path.splitext(filename)[0]
           
            # Save processed image as JSON
            processed_json_path = os.path.join(OUTPUT_DIR, f"{base_name}.json")
            with open(processed_json_path, 'w') as f:
                json.dump(processed_img.tolist(), f)
           
            # Save random values as JSON
            random_json_path = os.path.join(OUTPUT_DIR, f"{base_name}a.json")
            with open(random_json_path, 'w') as f:
                json.dump(random_values.tolist(), f)
           
            print(f"Processed {filename}")
           
        except Exception as e:
            print(f"Error processing {filename}: {e}")

def is_image_file(filename):
    """Check if a file is likely to be an image based on extension"""
    image_extensions = ['.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.gif']
    return any(filename.lower().endswith(ext) for ext in image_extensions)

# Execute the script
if __name__ == "__main__":
    print(f"Starting image processing from {INPUT_DIR} to {OUTPUT_DIR}")
    process_rgb_images()
    print(f"Processing complete. Modified images and random values saved to {OUTPUT_DIR}")