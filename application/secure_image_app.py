import sys
import os
import json
import random
import numpy as np
import base64
from PIL import Image, ImageQt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, QFileDialog, 
                             QProgressBar, QListWidget, QMessageBox, QFrame, QSplitter, 
                             QSizePolicy, QScrollArea, QGridLayout)
from PyQt5.QtGui import QPixmap, QFont, QIcon, QPalette, QColor, QImage
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize

# Constants
DEFAULT_STYLE = """
QMainWindow, QWidget {
    background-color: #f5f5f7;
    color: #333333;
}
QPushButton {
    background-color: #0071e3;
    color: white;
    border: none;
    border-radius: 5px;
    padding: 10px 15px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #0077ed;
}
QPushButton:disabled {
    background-color: #cccccc;
    color: #666666;
}
QLineEdit {
    border: 1px solid #cccccc;
    border-radius: 5px;
    padding: 8px;
    background-color: white;
}
QProgressBar {
    border: 1px solid #cccccc;
    border-radius: 5px;
    text-align: center;
    background-color: white;
}
QProgressBar::chunk {
    background-color: #0071e3;
    width: 10px;
}
QTabWidget::pane {
    border: 1px solid #cccccc;
    border-radius: 5px;
    background-color: white;
}
QTabBar::tab {
    background-color: #e0e0e0;
    border: 1px solid #cccccc;
    border-bottom: none;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    padding: 8px 15px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: white;
    border-bottom: none;
}
QListWidget {
    border: 1px solid #cccccc;
    border-radius: 5px;
    background-color: white;
    padding: 5px;
}
QLabel {
    padding: 5px;
}
"""

DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #1e1e1e;
    color: #f0f0f0;
}
QPushButton {
    background-color: #0071e3;
    color: white;
    border: none;
    border-radius: 5px;
    padding: 10px 15px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #0077ed;
}
QPushButton:disabled {
    background-color: #444444;
    color: #888888;
}
QLineEdit {
    border: 1px solid #444444;
    border-radius: 5px;
    padding: 8px;
    background-color: #2d2d2d;
    color: #f0f0f0;
}
QProgressBar {
    border: 1px solid #444444;
    border-radius: 5px;
    text-align: center;
    background-color: #2d2d2d;
    color: #f0f0f0;
}
QProgressBar::chunk {
    background-color: #0071e3;
    width: 10px;
}
QTabWidget::pane {
    border: 1px solid #444444;
    border-radius: 5px;
    background-color: #2d2d2d;
}
QTabBar::tab {
    background-color: #3d3d3d;
    border: 1px solid #444444;
    border-bottom: none;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    padding: 8px 15px;
    margin-right: 2px;
    color: #f0f0f0;
}
QTabBar::tab:selected {
    background-color: #2d2d2d;
    border-bottom: none;
}
QListWidget {
    border: 1px solid #444444;
    border-radius: 5px;
    background-color: #2d2d2d;
    color: #f0f0f0;
    padding: 5px;
}
QLabel {
    padding: 5px;
    color: #f0f0f0;
}
"""

def get_encryption_key(password):
    """Generate a Fernet encryption key from password"""
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
    """Encrypt data using the password"""
    key = get_encryption_key(password)
    fernet = Fernet(key)
    data_bytes = json.dumps(data).encode()
    encrypted_data = fernet.encrypt(data_bytes)
    return base64.b64encode(encrypted_data).decode()

def decrypt_data(encrypted_data, password):
    """Decrypt data using the password"""
    try:
        key = get_encryption_key(password)
        fernet = Fernet(key)
        data_bytes = base64.b64decode(encrypted_data)
        decrypted_data = fernet.decrypt(data_bytes)
        return json.loads(decrypted_data)
    except Exception as e:
        return None

class EncryptionWorker(QThread):
    progress_updated = pyqtSignal(int)
    file_processed = pyqtSignal(str)
    finished_processing = pyqtSignal()
    error_occurred = pyqtSignal(str, str)
    
    def __init__(self, input_files, output_dir, password):
        super().__init__()
        self.input_files = input_files
        self.output_dir = output_dir
        self.password = password
        
    def run(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        total_files = len(self.input_files)
        for i, file_path in enumerate(self.input_files):
            try:
                filename = os.path.basename(file_path)
                # Open image and ensure it's RGB
                img = Image.open(file_path)
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Convert image to numpy array for processing
                img_array = np.array(img)
                height, width, channels = img_array.shape
                
                # Generate random numbers for each pixel and channel
                random_values = np.zeros((height, width, channels), dtype=np.int32)
                processed_img = np.zeros((height, width, channels), dtype=np.int32)
                
                # For each pixel and channel, add a random number
                for h in range(height):
                    for w in range(width):
                        for c in range(channels):
                            # Get current pixel value
                            current_value = int(img_array[h, w, c])
                            random_val = random.randint(256, 999)
                            
                            # These are the lines we want to encrypt with the password
                            random_values[h, w, c] = current_value + random_val
                            processed_img[h, w, c] = random_val
                    
                    # Update progress after each row
                    if h % 10 == 0:
                        progress = int((i / total_files) * 100 + (h / height) * (100 / total_files))
                        self.progress_updated.emit(progress)
                
                # Get base name for output files
                base_name = os.path.splitext(filename)[0]
                
                # Save processed image as JSON (encrypted)
                processed_json_path = os.path.join(self.output_dir, f"{base_name}.json")
                encrypted_processed = encrypt_data(processed_img.tolist(), self.password)
                with open(processed_json_path, 'w') as f:
                    f.write(encrypted_processed)
                
                # Save random values as JSON (encrypted)
                random_json_path = os.path.join(self.output_dir, f"{base_name}a.json")
                encrypted_random = encrypt_data(random_values.tolist(), self.password)
                with open(random_json_path, 'w') as f:
                    f.write(encrypted_random)
                
                self.file_processed.emit(filename)
                
            except Exception as e:
                self.error_occurred.emit(filename, str(e))
                
            # Update overall progress
            progress = int(((i + 1) / total_files) * 100)
            self.progress_updated.emit(progress)
            
        self.finished_processing.emit()

class DecryptionWorker(QThread):
    progress_updated = pyqtSignal(int)
    file_processed = pyqtSignal(str, str)  # filename, output_path
    finished_processing = pyqtSignal()
    error_occurred = pyqtSignal(str, str)
    
    def __init__(self, input_dir, output_dir, password):
        super().__init__()
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.password = password
        
    def run(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Get all JSON files in the input directory
        all_files = os.listdir(self.input_dir)
        processed_files = [f for f in all_files if not f.endswith('a.json')]
        
        total_files = len(processed_files)
        for i, processed_filename in enumerate(processed_files):
            try:
                # Get base name and construct paths
                base_name = os.path.splitext(processed_filename)[0]
                processed_path = os.path.join(self.input_dir, processed_filename)
                random_path = os.path.join(self.input_dir, f"{base_name}a.json")
                
                # Check if both files exist
                if not os.path.exists(random_path):
                    self.error_occurred.emit(processed_filename, "Missing random values file")
                    continue
                
                # Load encrypted JSON data
                with open(processed_path, 'r') as f:
                    encrypted_processed = f.read()
                
                with open(random_path, 'r') as f:
                    encrypted_random = f.read()
                
                # Decrypt data
                processed_data = decrypt_data(encrypted_processed, self.password)
                random_data = decrypt_data(encrypted_random, self.password)
                
                if processed_data is None or random_data is None:
                    self.error_occurred.emit(processed_filename, "Decryption failed. Incorrect password?")
                    continue
                
                # Convert to numpy arrays
                processed_array = np.array(processed_data, dtype=np.int32)
                random_array = np.array(random_data, dtype=np.int32)
                
                # Reconstruct original image by subtracting random values
                original_array = np.array(random_array - processed_array, dtype=np.uint8)
                
                # Create PIL image from numpy array
                reconstructed_img = Image.fromarray(original_array)
                
                # Save reconstructed image
                output_path = os.path.join(self.output_dir, f"{base_name}.png")
                reconstructed_img.save(output_path)
                
                self.file_processed.emit(base_name, output_path)
                
            except Exception as e:
                self.error_occurred.emit(processed_filename, str(e))
            
            # Update overall progress
            progress = int(((i + 1) / total_files) * 100)
            self.progress_updated.emit(progress)
            
        self.finished_processing.emit()

class ImageThumbnail(QWidget):
    def __init__(self, image_path, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.image_path = image_path
        
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        self.name_label = QLabel(os.path.basename(image_path))
        self.name_label.setAlignment(Qt.AlignCenter)
        
        if os.path.exists(image_path):
            pixmap = QPixmap(image_path)
            if not pixmap.isNull():
                pixmap = pixmap.scaled(150, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.image_label.setPixmap(pixmap)
                self.layout.addWidget(self.image_label)
                self.layout.addWidget(self.name_label)
                
                # Set fixed size for consistency
                self.setFixedSize(170, 200)
                
                # Add a border
                self.setStyleSheet("border: 1px solid #cccccc; border-radius: 5px; background-color: white; margin: 3px;")
            else:
                # Handle invalid image
                self.name_label.setText(f"Invalid image: {os.path.basename(image_path)}")
                self.layout.addWidget(self.name_label)
        else:
            # Handle missing file
            self.name_label.setText(f"File not found: {os.path.basename(image_path)}")
            self.layout.addWidget(self.name_label)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Initialize UI
        self.setWindowTitle("SecureImage Encrypt/Decrypt")
        self.setMinimumSize(900, 600)
        
        # Set application icon
        self.setWindowIcon(QIcon("lock.ico"))  # You'll need to create/add this icon file
        
        # Create central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)
        
        # Create encrypt and decrypt tabs
        self.encrypt_tab = QWidget()
        self.decrypt_tab = QWidget()
        self.tab_widget.addTab(self.encrypt_tab, "Encrypt Images")
        self.tab_widget.addTab(self.decrypt_tab, "Decrypt Images")
        
        # Setup each tab
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        
        # Add theme toggle button
        self.theme_button = QPushButton("Toggle Dark Mode")
        self.theme_button.clicked.connect(self.toggle_theme)
        self.main_layout.addWidget(self.theme_button)
        
        # Set default style
        self.dark_mode = False
        self.setStyleSheet(DEFAULT_STYLE)
        
    def setup_encrypt_tab(self):
        # Main layout for encrypt tab
        encrypt_layout = QVBoxLayout(self.encrypt_tab)
        
        # Instructions
        instructions = QLabel("Select images to encrypt. The images will be processed and saved as encrypted JSON files.")
        instructions.setAlignment(Qt.AlignCenter)
        encrypt_layout.addWidget(instructions)
        
        # Input section
        input_section = QFrame()
        input_layout = QHBoxLayout(input_section)
        
        # File selection
        file_select_btn = QPushButton("Select Images")
        file_select_btn.clicked.connect(self.select_files)
        input_layout.addWidget(file_select_btn)
        
        # Selected files label
        self.selected_files_label = QLabel("No files selected")
        input_layout.addWidget(self.selected_files_label)
        
        # Output directory selection
        out_dir_btn = QPushButton("Output Directory")
        out_dir_btn.clicked.connect(self.select_encrypt_output_dir)
        input_layout.addWidget(out_dir_btn)
        
        # Output directory label
        self.encrypt_output_dir_label = QLabel("No directory selected")
        input_layout.addWidget(self.encrypt_output_dir_label)
        
        encrypt_layout.addWidget(input_section)
        
        # Password section
        password_section = QFrame()
        password_layout = QHBoxLayout(password_section)
        
        password_label = QLabel("Encryption Password:")
        password_layout.addWidget(password_label)
        
        self.encrypt_password = QLineEdit()
        self.encrypt_password.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(self.encrypt_password)
        
        encrypt_layout.addWidget(password_section)
        
        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt Images")
        self.encrypt_button.clicked.connect(self.start_encryption)
        self.encrypt_button.setEnabled(False)
        encrypt_layout.addWidget(self.encrypt_button)
        
        # Progress bar
        self.encrypt_progress = QProgressBar()
        encrypt_layout.addWidget(self.encrypt_progress)
        
        # Processed files list
        processed_label = QLabel("Processed Files:")
        encrypt_layout.addWidget(processed_label)
        
        self.processed_files = QListWidget()
        encrypt_layout.addWidget(self.processed_files)
        
        # Preview section
        preview_label = QLabel("Image Previews:")
        encrypt_layout.addWidget(preview_label)
        
        self.preview_scroll_area = QScrollArea()
        self.preview_scroll_area.setWidgetResizable(True)
        
        self.preview_container = QWidget()
        self.preview_layout = QGridLayout(self.preview_container)
        self.preview_scroll_area.setWidget(self.preview_container)
        
        encrypt_layout.addWidget(self.preview_scroll_area)
        
        # Store selected files
        self.selected_files = []
        self.encrypt_output_dir = ""
        
    def setup_decrypt_tab(self):
        # Main layout for decrypt tab
        decrypt_layout = QVBoxLayout(self.decrypt_tab)
        
        # Instructions
        instructions = QLabel("Select a directory containing encrypted JSON files to decrypt them back to images.")
        instructions.setAlignment(Qt.AlignCenter)
        decrypt_layout.addWidget(instructions)
        
        # Input section
        input_section = QFrame()
        input_layout = QHBoxLayout(input_section)
        
        # Input directory selection
        in_dir_btn = QPushButton("Input Directory")
        in_dir_btn.clicked.connect(self.select_decrypt_input_dir)
        input_layout.addWidget(in_dir_btn)
        
        # Input directory label
        self.decrypt_input_dir_label = QLabel("No directory selected")
        input_layout.addWidget(self.decrypt_input_dir_label)
        
        # Output directory selection
        out_dir_btn = QPushButton("Output Directory")
        out_dir_btn.clicked.connect(self.select_decrypt_output_dir)
        input_layout.addWidget(out_dir_btn)
        
        # Output directory label
        self.decrypt_output_dir_label = QLabel("No directory selected")
        input_layout.addWidget(self.decrypt_output_dir_label)
        
        decrypt_layout.addWidget(input_section)
        
        # Password section
        password_section = QFrame()
        password_layout = QHBoxLayout(password_section)
        
        password_label = QLabel("Decryption Password:")
        password_layout.addWidget(password_label)
        
        self.decrypt_password = QLineEdit()
        self.decrypt_password.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(self.decrypt_password)
        
        decrypt_layout.addWidget(password_section)
        
        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt Images")
        self.decrypt_button.clicked.connect(self.start_decryption)
        self.decrypt_button.setEnabled(False)
        decrypt_layout.addWidget(self.decrypt_button)
        
        # Progress bar
        self.decrypt_progress = QProgressBar()
        decrypt_layout.addWidget(self.decrypt_progress)
        
        # Reconstructed files list
        reconstructed_label = QLabel("Reconstructed Files:")
        decrypt_layout.addWidget(reconstructed_label)
        
        self.reconstructed_files = QListWidget()
        decrypt_layout.addWidget(self.reconstructed_files)
        
        # Preview section
        preview_label = QLabel("Image Previews:")
        decrypt_layout.addWidget(preview_label)
        
        self.decrypt_preview_scroll_area = QScrollArea()
        self.decrypt_preview_scroll_area.setWidgetResizable(True)
        
        self.decrypt_preview_container = QWidget()
        self.decrypt_preview_layout = QGridLayout(self.decrypt_preview_container)
        self.decrypt_preview_scroll_area.setWidget(self.decrypt_preview_container)
        
        decrypt_layout.addWidget(self.decrypt_preview_scroll_area)
        
        # Store directories
        self.decrypt_input_dir = ""
        self.decrypt_output_dir = ""
        
    def select_files(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Images to Encrypt", "", 
            "Image Files (*.png *.jpg *.jpeg *.bmp *.tiff)"
        )
        if files:
            self.selected_files = files
            self.selected_files_label.setText(f"{len(files)} files selected")
            self.update_encrypt_button_state()
            
            # Clear and update preview
            self.clear_layout(self.preview_layout)
            
            # Add thumbnails in a grid
            for i, file_path in enumerate(files[:12]):  # Limit to first 12 images
                row, col = divmod(i, 4)
                thumbnail = ImageThumbnail(file_path)
                self.preview_layout.addWidget(thumbnail, row, col)
                
    def select_encrypt_output_dir(self):
        directory = QFileDialog.getExistingDirectory(
            self, "Select Output Directory for Encrypted Files"
        )
        if directory:
            self.encrypt_output_dir = directory
            self.encrypt_output_dir_label.setText(os.path.basename(directory) or directory)
            self.update_encrypt_button_state()
            
    def select_decrypt_input_dir(self):
        directory = QFileDialog.getExistingDirectory(
            self, "Select Directory with Encrypted JSON Files"
        )
        if directory:
            self.decrypt_input_dir = directory
            self.decrypt_input_dir_label.setText(os.path.basename(directory) or directory)
            self.update_decrypt_button_state()
            
    def select_decrypt_output_dir(self):
        directory = QFileDialog.getExistingDirectory(
            self, "Select Output Directory for Decrypted Images"
        )
        if directory:
            self.decrypt_output_dir = directory
            self.decrypt_output_dir_label.setText(os.path.basename(directory) or directory)
            self.update_decrypt_button_state()
            
    def update_encrypt_button_state(self):
        self.encrypt_button.setEnabled(
            bool(self.selected_files) and 
            bool(self.encrypt_output_dir) and 
            bool(self.encrypt_password.text())
        )
        
    def update_decrypt_button_state(self):
        self.decrypt_button.setEnabled(
            bool(self.decrypt_input_dir) and 
            bool(self.decrypt_output_dir) and 
            bool(self.decrypt_password.text())
        )
        
    def clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
            else:
                self.clear_layout(item.layout())
                
    def start_encryption(self):
        # Check if password is provided
        password = self.encrypt_password.text()
        if not password:
            QMessageBox.warning(self, "No Password", "Please enter an encryption password.")
            return
            
        # Clear previous results
        self.processed_files.clear()
        self.encrypt_progress.setValue(0)
        
        # Create and start worker thread
        self.encrypt_worker = EncryptionWorker(
            self.selected_files,
            self.encrypt_output_dir,
            password
        )
        
        # Connect signals
        self.encrypt_worker.progress_updated.connect(self.encrypt_progress.setValue)
        self.encrypt_worker.file_processed.connect(self.add_processed_file)
        self.encrypt_worker.error_occurred.connect(self.show_encryption_error)
        self.encrypt_worker.finished_processing.connect(self.encryption_finished)
        
        # Disable UI during processing
        self.encrypt_button.setEnabled(False)
        self.encrypt_button.setText("Encrypting...")
        
        # Start processing
        self.encrypt_worker.start()
        
    def add_processed_file(self, filename):
        self.processed_files.addItem(filename)
        
    def show_encryption_error(self, filename, error_message):
        self.processed_files.addItem(f"Error with {filename}: {error_message}")
        
    def encryption_finished(self):
        self.encrypt_button.setEnabled(True)
        self.encrypt_button.setText("Encrypt Images")
        QMessageBox.information(
            self, 
            "Encryption Complete", 
            f"All images have been encrypted and saved to: {self.encrypt_output_dir}"
        )
        
    def start_decryption(self):
        # Check if password is provided
        password = self.decrypt_password.text()
        if not password:
            QMessageBox.warning(self, "No Password", "Please enter a decryption password.")
            return
            
        # Clear previous results
        self.reconstructed_files.clear()
        self.decrypt_progress.setValue(0)
        self.clear_layout(self.decrypt_preview_layout)
        
        # Create and start worker thread
        self.decrypt_worker = DecryptionWorker(
            self.decrypt_input_dir,
            self.decrypt_output_dir,
            password
        )
        
        # Connect signals
        self.decrypt_worker.progress_updated.connect(self.decrypt_progress.setValue)
        self.decrypt_worker.file_processed.connect(self.add_reconstructed_file)
        self.decrypt_worker.error_occurred.connect(self.show_decryption_error)
        self.decrypt_worker.finished_processing.connect(self.decryption_finished)
        
        # Disable UI during processing
        self.decrypt_button.setEnabled(False)
        self.decrypt_button.setText("Decrypting...")
        
        # Start processing
        self.decrypt_worker.start()
        
    def add_reconstructed_file(self, filename, output_path):
        self.reconstructed_files.addItem(filename)
        
        # Add to preview grid
        count = self.decrypt_preview_layout.count()
        row, col = divmod(count, 4)
        thumbnail = ImageThumbnail(output_path)
        self.decrypt_preview_layout.addWidget(thumbnail, row, col)
        
    def show_decryption_error(self, filename, error_message):
        self.reconstructed_files.addItem(f"Error with {filename}: {error_message}")
        
    def decryption_finished(self):
        self.decrypt_button.setEnabled(True)
        self.decrypt_button.setText("Decrypt Images")
        QMessageBox.information(
            self, 
            "Decryption Complete", 
            f"All images have been decrypted and saved to: {self.decrypt_output_dir}"
        )
        
    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.setStyleSheet(DARK_STYLE)
            self.theme_button.setText("Toggle Light Mode")
        else:
            self.setStyleSheet(DEFAULT_STYLE)
            self.theme_button.setText("Toggle Dark Mode")
            
    def closeEvent(self, event):
        # Clean up any background threads when closing
        if hasattr(self, 'encrypt_worker') and self.encrypt_worker.isRunning():
            self.encrypt_worker.terminate()
            self.encrypt_worker.wait()
            
        if hasattr(self, 'decrypt_worker') and self.decrypt_worker.isRunning():
            self.decrypt_worker.terminate()
            self.decrypt_worker.wait()
            
        super().closeEvent(event)

if __name__ == "__main__":
    # Set high DPI scaling
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    # Create and show application
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())