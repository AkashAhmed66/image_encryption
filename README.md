# 🔐 Image Encryption with Random Pixel Addition

## ✨ Overview

This project provides a simple yet effective method to encrypt RGB images by adding random values to each pixel channel. The encrypted images and their corresponding keys are stored as JSON files, making it difficult to reconstruct the original image without the key.

## 🧩 How It Works

The encryption process follows these steps:

1. Each RGB image is read as a 3D array (height × width × 3 channels)
2. For each pixel channel, a random value is generated and added to the original value
3. The modified image and the random values (the key) are saved as separate JSON files
4. Without the key file, reconstructing the original image is computationally difficult

The decryption process reverses these steps:

1. The encrypted image JSON and random key JSON are loaded
2. The random values are subtracted from the encrypted pixel values
3. The original image is reconstructed and saved

## 📁 Project Structure

```
├── input_images/       # Original image files to be encrypted
├── output_json/        # Encrypted images and keys as JSON
├── view_images/        # Reconstructed (decrypted) images
├── make.py             # Encryption script
├── break.py            # Decryption script
└── README.md           # This documentation
```

## 🚀 Usage

### 🔒 Encryption

```bash
python make.py
```

This processes all images in the `input_images` directory and generates:
- `{image_name}.json` - The encrypted image data
- `{image_name}a.json` - The key file (the "a" representing my initial)

### 🔓 Decryption

```bash
python break.py
```

This reconstructs the original images using the pair of JSON files and saves them to the `view_images` directory.

## 💡 Applications and Importance

### 🛡️ Security Applications

- **Image Steganography**: The encryption can be used to hide sensitive images
- **Digital Watermarking**: Can be modified to embed ownership information
- **Content Protection**: Distributing encrypted images with controlled key access

### ⚙️ Technical Benefits

- **Simple Implementation**: Uses basic arithmetic operations but creates effective encryption
- **Format Independence**: Works on any RGB image format (PNG, JPG, BMP, etc.)
- **Minimal Artifacts**: Unlike some encryption methods, this preserves exact pixel values

### 📚 Educational Value

- Demonstrates fundamental concepts of encryption (message + key)
- Shows practical application of NumPy and PIL libraries
- Provides a simple introduction to image processing techniques

## 🔍 Technical Details

### 🧮 Encryption Algorithm

For each pixel channel value `V` in the original image:
1. Calculate maximum possible addition: `max_add = 255 - V`
2. Generate random value `R` between 0 and `max_add`
3. Store encrypted value `E = V + R`
4. Store key value `R`

This ensures that no pixel value exceeds 255 (the maximum for 8-bit color channels).

### 🔄 Decryption Algorithm

For each pixel channel value `E` in the encrypted image with corresponding key value `R`:
1. Calculate original value: `V = E - R`
2. Reconstruct the original image

## 🖼️ Example

Original Image | Encrypted JSON | Decrypted Image
:------------:|:--------------:|:---------------:
![Original](https://via.placeholder.com/150?text=Original) | `[[[120,45,78],...]]` | ![Decrypted](https://via.placeholder.com/150?text=Decrypted)

## 🔮 Future Improvements

- Add command-line arguments for directory specification
- Implement more sophisticated random number generation
- Add support for password-protected encryption
- Extend to other image formats (grayscale, RGBA)

## 📜 License

[MIT License](LICENSE)

## 👨‍💻 Author

Akash Ahmed
