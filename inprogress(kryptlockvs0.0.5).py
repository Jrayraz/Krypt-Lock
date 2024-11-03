import os
import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QFileDialog, QMessageBox, QLabel, QVBoxLayout, QHBoxLayout, QListWidget, QDialog, QWidget, QInputDialog, QLineEdit
from PySide6.QtCore import Qt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from threading import Thread
import logging
import base64
import time

# Set up logging
logging.basicConfig(filename='kryptlock.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class KryptLockApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KryptLock")
        self.setGeometry(100, 100, 400, 800)  # Updated height from 600 to 800
        self.key = None
        self.watch_directories = []

        self.initUI()

    def initUI(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()

        self.krypt_data_button = QPushButton("Krypt Data")
        self.krypt_data_button.setStyleSheet("background-color: black; color: yellow; font: bold 14px 'Old English Text MT'; height: 48px;")
        self.krypt_data_button.clicked.connect(self.krypt_data)
        layout.addWidget(self.krypt_data_button)

        self.dekrypt_data_button = QPushButton("DeKrypt Data")
        self.dekrypt_data_button.setStyleSheet("background-color: black; color: yellow; font: bold 14px 'Old English Text MT'; height: 48px;")
        self.dekrypt_data_button.clicked.connect(self.dekrypt_data)
        layout.addWidget(self.dekrypt_data_button)

        self.krypt_directory_button = QPushButton("Krypt Directory")
        self.krypt_directory_button.setStyleSheet("background-color: black; color: yellow; font: bold 14px 'Old English Text MT'; height: 48px;")
        self.krypt_directory_button.clicked.connect(self.krypt_directory)
        layout.addWidget(self.krypt_directory_button)

        self.dekrypt_directory_button = QPushButton("DeKrypt Directory")
        self.dekrypt_directory_button.setStyleSheet("background-color: black; color: yellow; font: bold 14px 'Old English Text MT'; height: 48px;")
        self.dekrypt_directory_button.clicked.connect(self.dekrypt_directory)
        layout.addWidget(self.dekrypt_directory_button)

        self.create_key_button = QPushButton("Create a New Key")
        self.create_key_button.setStyleSheet("background-color: black; color: yellow; font: bold 14px 'Old English Text MT'; height: 48px;")
        self.create_key_button.clicked.connect(self.create_key)
        layout.addWidget(self.create_key_button)

        self.save_key_button = QPushButton("Save Key")
        self.save_key_button.setStyleSheet("background-color: black; color: yellow; font: bold 14px 'Old English Text MT'; height: 48px;")
        self.save_key_button.clicked.connect(self.save_key)
        layout.addWidget(self.save_key_button)

        self.load_key_button = QPushButton("Load Key")
        self.load_key_button.setStyleSheet("background-color: black; color: yellow; font: bold 14px 'Old English Text MT'; height: 48px;")
        self.load_key_button.clicked.connect(self.load_key)
        layout.addWidget(self.load_key_button)
    
        # AutoKrypt Section
        autokrypt_label = QLabel("AutoKrypt")
        autokrypt_label.setAlignment(Qt.AlignCenter)
        autokrypt_label.setStyleSheet("font: bold 14px 'Old English Text MT'; color: red;")
        layout.addWidget(autokrypt_label, alignment=Qt.AlignBottom)  # Adjusted position

        autokrypt_layout = QHBoxLayout()
        self.execute_button = QPushButton("Execute")
        self.execute_button.setStyleSheet("background-color: red; color: yellow; font: bold 14px 'Old English Text MT'; height: 48px;")
        self.execute_button.clicked.connect(self.start_autokrypt)

        self.manage_directories_button = QPushButton("Manage Directories")
        self.manage_directories_button.setStyleSheet("background-color: red; color: yellow; font: bold 14px 'Old English Text MT'; height: 48px;")
        self.manage_directories_button.clicked.connect(self.manage_directories)

        self.select_key_button = QPushButton("Select Key")
        self.select_key_button.setStyleSheet("background-color: red; color: yellow; font: bold 14px 'Old English Text MT'; height: 48px;")
        self.select_key_button.clicked.connect(self.load_key)

        autokrypt_layout.addWidget(self.execute_button, stretch=3)
        autokrypt_layout.addWidget(self.manage_directories_button, stretch=1)
        autokrypt_layout.addWidget(self.select_key_button, stretch=1)

        layout.addLayout(autokrypt_layout)
        central_widget.setLayout(layout)

    def load_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Key File", "", "Key Files (*.key);;All Files (*)")
        if file_path:
            password, ok = QInputDialog.getText(self, "Password", "Enter password:", QLineEdit.Password)
            if not ok or not password:
                QMessageBox.critical(self, "Error", "Password is required to load the key.")
                return
            try:
                with open(file_path, 'rb') as file:
                    salt = file.read(16)
                    encrypted_key = file.read()
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                fernet = Fernet(key)
                self.key = fernet.decrypt(encrypted_key)
                QMessageBox.information(self, "Success", "Key loaded successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load key: {e}")

    def save_key(self):
        try:
            if not hasattr(self, 'key'):
                QMessageBox.critical(self, "Error", "No key to save. Please create a key first.")
                return
            password, ok = QInputDialog.getText(self, "Password", "Enter password:", QLineEdit.Password)
            if not ok or not password:
                QMessageBox.critical(self, "Error", "Password is required to save the key.")
                return
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            fernet = Fernet(key)
            encrypted_key = fernet.encrypt(self.key)
            file_path, _ = QFileDialog.getSaveFileName(self, "Save Key File", "", "Key Files (*.key);;All Files (*)")
            if file_path:
                with open(file_path, 'wb') as file:
                    file.write(salt)
                    file.write(encrypted_key)
                QMessageBox.information(self, "Success", "Key saved successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save key: {e}")
    
    def krypt_data(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt", "", "All Files (*)")
            if not file_path:
                return
            with open(file_path, 'rb') as file:
                data = file.read()
            encrypted_data = self.encrypt(data)
            with open(file_path + '.krypt', 'wb') as file:
                file.write(encrypted_data)
            os.remove(file_path)
            QMessageBox.information(self, "Krypt Data", "Data encrypted successfully.")
            logging.info("Data encrypted successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")
            logging.error(f"An error occurred during data encryption: {e}")

    def dekrypt_data(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt", "", "Krypt Files (*.krypt);;All Files (*)")
            if not file_path:
                return
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            decrypted_data = self.decrypt(encrypted_data)
            new_file_path = file_path.replace('.krypt', '')
            with open(new_file_path, 'wb') as file:
                file.write(decrypted_data)
            os.remove(file_path)
            QMessageBox.information(self, "DeKrypt Data", "Data decrypted successfully.")
            logging.info("Data decrypted successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")
            logging.error(f"An error occurred during data decryption: {e}")

    def krypt_directory(self):
        try:
            dir_path = QFileDialog.getExistingDirectory(self, "Select Directory to Encrypt")
            if not dir_path:
                return
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    encrypted_data = self.encrypt(data)
                    with open(file_path + '.krypt', 'wb') as f:
                        f.write(encrypted_data)
                    os.remove(file_path)
            QMessageBox.information(self, "Krypt Directory", "Directory encrypted successfully.")
            logging.info("Directory encrypted successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")
            logging.error(f"An error occurred during directory encryption: {e}")

    def dekrypt_directory(self):
        try:
            dir_path = QFileDialog.getExistingDirectory(self, "Select Directory to Decrypt")
            if not dir_path:
                return
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    if file.endswith('.krypt'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'rb') as f:
                            encrypted_data = f.read()
                        decrypted_data = self.decrypt(encrypted_data)
                        new_file_path = file_path.replace('.krypt', '')
                        with open(new_file_path, 'wb') as f:
                            f.write(decrypted_data)
                        os.remove(file_path)
            QMessageBox.information(self, "DeKrypt Directory", "Directory decrypted successfully.")
            logging.info("Directory decrypted successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")
            logging.error(f"An error occurred during directory decryption: {e}")

    def create_key(self):
        try:
            self.key = AESGCM.generate_key(bit_length=256)
            QMessageBox.information(self, "Create Key", "Key created successfully.")
            logging.info("Key created successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")
            logging.error(f"An error occurred during key creation: {e}")

    def encrypt(self, data):
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.key)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        return nonce + encrypted_data

    def decrypt(self, encrypted_data):
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def start_autokrypt(self):
        if not self.key:
            QMessageBox.critical(self, "Error", "Please load a key first.")
            return

        if not self.watch_directories:
            QMessageBox.critical(self, "Error", "Please add directories to AutoKrypt.")
            return

        previous_contents = {d: set(os.listdir(d)) for d in self.watch_directories}

        while True:
            time.sleep(1)  # Check for changes every second
            for directory in self.watch_directories:
                current_contents = set(os.listdir(directory))
                new_files = current_contents - previous_contents[directory]

                for new_file in new_files:
                    new_file_path = os.path.join(directory, new_file)
                    if os.path.isdir(new_file_path):
                        for root, _, files in os.walk(new_file_path):
                            for file in files:
                                file_path = os.path.join(root, file)
                                self.encrypt_file(file_path)
                    else:
                        self.encrypt_file(new_file_path)

                previous_contents[directory] = current_contents

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            original = file.read()
        encrypted = self.encrypt(original)
        with open(file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
        logging.info(f"File encrypted: {file_path}")

    def manage_directories(self):
        manage_window = QDialog(self)
        manage_window.setWindowTitle("Manage Directories")
        manage_window.setGeometry(100, 100, 400, 400)
        
        layout = QVBoxLayout()
        listbox = QListWidget()
        
        for directory in self.watch_directories:
            listbox.addItem(directory)

        add_button = QPushButton("Add Directory")
        add_button.clicked.connect(lambda: self.add_directory(listbox))
        remove_button = QPushButton("Remove Directory")
        remove_button.clicked.connect(lambda: self.remove_directory(listbox))

        layout.addWidget(listbox)
        layout.addWidget(add_button)
        layout.addWidget(remove_button)

        manage_window.setLayout(layout)
        manage_window.exec_()

    def add_directory(self, listbox):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory and directory not in self.watch_directories:
            self.watch_directories.append(directory)
            listbox.addItem(directory)

    def remove_directory(self, listbox):
        selected_item = listbox.currentItem()
        if selected_item:
            directory = selected_item.text()
            self.watch_directories.remove(directory)
            listbox.takeItem(listbox.row(selected_item))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    krypt_lock_app = KryptLockApp()
    krypt_lock_app.show()
    sys.exit(app.exec())

