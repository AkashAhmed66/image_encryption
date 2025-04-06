from cx_Freeze import setup, Executable
import sys

# Dependencies
build_exe_options = {
    "packages": ["os", "sys", "numpy", "PIL", "json", "random", "base64", 
                 "cryptography"],
    "includes": ["PyQt5.QtCore", "PyQt5.QtGui", "PyQt5.QtWidgets"],
    "excludes": ["tkinter", "matplotlib", "scipy", "PyQt5.QtQml", "PyQt5.Qt3D"],
    "include_files": ["README.md", "lock.ico"],
    "include_msvcr": True,
}

# Base for Windows systems
base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(
    name="SecureImage",
    version="1.0",
    description="Secure Image Encryption and Decryption Application",
    author="Your Name",
    options={"build_exe": build_exe_options},
    executables=[
        Executable(
            "secure_image_app.py", 
            base=base,
            target_name="SecureImage.exe",
            icon="lock.ico"
        )
    ]
)