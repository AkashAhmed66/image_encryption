import json
import numpy as np
from PIL import Image
import os

def json_to_image(input_json_path, output_image_path):
    """
    Convert JSON pixel data to image file
    :param input_json_path: Path to input JSON file
    :param output_image_path: Path to save output image
    """
    try:
        # Load JSON data
        with open(input_json_path, 'r') as f:
            pixel_data = json.load(f)
        
        # Convert to numpy array
        np_array = np.clip(np.array(pixel_data), 0, 255).astype(np.uint8)
        
        # Verify array dimensions
        if len(np_array.shape) != 3 or np_array.shape[2] != 3:
            raise ValueError("Invalid JSON structure. Expected 3D array with RGB channels")
        
        # Create image from array
        img = Image.fromarray(np_array)
        
        # Create output directory if needed
        os.makedirs(os.path.dirname(output_image_path), exist_ok=True)
        
        # Save image
        img.save(output_image_path)
        print(f"Image successfully saved to {output_image_path}")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    # ==============================================
    # Configure paths here
    # ==============================================
    
    # Example 1: Relative paths
    INPUT_JSON = "output_json/imagea.json"    # Path to your input JSON file
    OUTPUT_IMAGE = "view_images/reconstructed.png"  # Path for output image
    
    # Example 2: Absolute paths (uncomment to use)
    # INPUT_JSON = r"C:\Users\Username\project\output_json\image.json"
    # OUTPUT_IMAGE = r"C:\Users\Username\project\view_images\reconstructed.jpg"
    
    # Example 3: Linux/Mac paths (uncomment to use)
    # INPUT_JSON = "/home/user/project/output_json/image.json"
    # OUTPUT_IMAGE = "/home/user/project/view_images/reconstructed.tiff"
    
    # ==============================================
    # Don't modify below this line
    # ==============================================
    
    # Run conversion
    json_to_image(INPUT_JSON, OUTPUT_IMAGE)