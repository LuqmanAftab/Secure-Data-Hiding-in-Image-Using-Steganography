import cv2
import numpy as np
from PIL import Image
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import base64
import hashlib
import tkinter as tk
from tkinter import filedialog


class SecureImageSteganography:
    def __init__(self, key=None):
        """
        Initialize the steganography class with an optional encryption key.
        If no key is provided, a new one will be generated.
        
        Args:
            key (bytes, optional): AES encryption key (must be 16, 24, or 32 bytes)
        """
        self.key = key
            
    def encrypt_message(self, message, password):
        """
        Encrypt a message using AES in CBC mode with random IV.
        
        Args:
            message (str): Message to encrypt
            password (str): Password to derive encryption key
            
        Returns:
            tuple: (iv, ciphertext) both as bytes
        """
        # Derive key from password
        key = hashlib.sha256(password.encode()).digest()
        
        # Generate a random initialization vector
        iv = get_random_bytes(16)
        
        # Create the AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the message to be a multiple of 16 bytes and encrypt
        padded_message = pad(message.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        
        return iv, ciphertext
    
    def decrypt_message(self, iv, ciphertext, password):
        """
        Decrypt an AES-encrypted message.
        
        Args:
            iv (bytes): Initialization vector used for encryption
            ciphertext (bytes): Encrypted message
            password (str): Password to derive decryption key
            
        Returns:
            str: Decrypted message
        """
        # Derive key from password
        key = hashlib.sha256(password.encode()).digest()
        
        # Create the AES cipher for decryption
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad
        try:
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted_message = unpad(decrypted_padded, AES.block_size)
            return decrypted_message.decode('utf-8')
        except (ValueError, KeyError):
            return None  # Indicates decryption failure (wrong password)
    
    def bytes_to_binary(self, data):
        """
        Convert bytes to a binary string.
        
        Args:
            data (bytes): Input bytes
            
        Returns:
            str: Binary representation as string of 0s and 1s
        """
        binary = ''
        for byte in data:
            # Convert each byte to an 8-bit binary string
            binary += format(byte, '08b')
        return binary
    
    def binary_to_bytes(self, binary_str):
        """
        Convert a binary string back to bytes.
        
        Args:
            binary_str (str): Binary string of 0s and 1s
            
        Returns:
            bytes: Reconstructed bytes
        """
        bytes_list = []
        # Process 8 bits at a time
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            bytes_list.append(int(byte, 2))
        return bytes(bytes_list)
    

    def embed_data(self, image_path, message, password, output_path=None):
        try:
            # Load image using OpenCV
            img = cv2.imread(image_path)
            if img is None:
                print("Error: Unable to load image.")
                return None
            
            # Convert image to RGB (OpenCV loads in BGR format)
            img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            
            # Get image dimensions
            height, width, channels = img.shape

            # Encrypt the message
            iv, ciphertext = self.encrypt_message(message, password)

            # Create a header with the length of the ciphertext and IV
            header = len(ciphertext).to_bytes(4, byteorder='big')

            # Full data to hide
            full_data = header + iv + ciphertext

            # Convert to binary
            binary_data = self.bytes_to_binary(full_data)
            data_len = len(binary_data)

            # Calculate required pixels
            pixels_needed = data_len
            pixels_available = height * width * channels

            # Check if the image can store the data
            if pixels_needed > pixels_available:
                print("Error: Image is too small to store the data.")
                return None

            print(f"Data length: {data_len} bits")

            # Embed data bit by bit
            data_index = 0
            for i in range(height):
                for j in range(width):
                    for k in range(channels):
                        if data_index < data_len:
                            # Get the bit to embed
                            bit = int(binary_data[data_index])
                            # Modify the LSB
                            img[i, j, k] = (img[i, j, k] & 0xFE) | bit
                            data_index += 1
                        else:
                            break

            # Convert image back to BGR before saving (since OpenCV saves in BGR format)
            img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)

            # Save the image
            if output_path is None:
                name, ext = os.path.splitext(image_path)
                output_path = f"{name}_stego.png"

            cv2.imwrite(output_path, img)
            return output_path

        except Exception as e:
            print(f"Error during embedding: {str(e)}")
            return None

    def extract_data(self, stego_image_path, password):
        """
        Extract and decrypt hidden message from a stego image.
        
        Args:
            stego_image_path (str): Path to the stego image
            password (str): Password for decryption
            
        Returns:
            str: Decrypted message or None if failed
        """
        try:
            # Load the image
            stego_img = Image.open(stego_image_path)
            
            # Convert to RGB if needed
            if stego_img.mode != 'RGB':
                stego_img = stego_img.convert('RGB')
                
            stego_array = np.array(stego_img, dtype=np.uint8)
            
            # Get dimensions
            height, width, channels = stego_array.shape
            
            # Extract LSBs
            binary_data = ''
            exit_loops = False
            
            for i in range(height):
                if exit_loops:
                    break
                    
                for j in range(width):
                    if exit_loops:
                        break
                        
                    for k in range(channels):
                        # Extract the LSB
                        bit = stego_array[i, j, k] & 1
                        binary_data += str(bit)
                        
                        # Stop once we have at least the header (32 bits)
                        if len(binary_data) >= 32 and len(binary_data) % 8 == 0:
                            # Try to extract the length
                            header_bytes = self.binary_to_bytes(binary_data[:32])
                            try:
                                ciphertext_length = int.from_bytes(header_bytes, byteorder='big')
                                
                                # Validate ciphertext length
                                if ciphertext_length <= 0 or ciphertext_length > 1000000:  # Set a reasonable upper limit
                                    continue  # Skip invalid lengths and continue collecting bits
                                    
                                total_bits_needed = 32 + 128 + (ciphertext_length * 8)
                                
                                # If we have all the bits we need, stop extracting
                                if len(binary_data) >= total_bits_needed:
                                    binary_data = binary_data[:total_bits_needed]
                                    print(f"Extracted data length: {len(binary_data)} bits")
                                    print(f"Detected ciphertext length: {ciphertext_length} bytes")
                                    exit_loops = True
                                    break
                            except ValueError:
                                # Continue collecting bits if we can't parse the length yet
                                pass
            
            # Ensure we have at least enough data for the header
            if len(binary_data) < 32:
                print("Not enough data extracted for header.")
                return None
                
            # Extract header (first 32 bits/4 bytes)
            header_binary = binary_data[:32]
            header_bytes = self.binary_to_bytes(header_binary)
            ciphertext_length = int.from_bytes(header_bytes, byteorder='big')
            
            # Validate ciphertext length
            if ciphertext_length <= 0 or ciphertext_length > (len(binary_data) - 32 - 128) // 8:
                print(f"Invalid ciphertext length: {ciphertext_length}")
                return None
                
            # Extract IV (next 128 bits/16 bytes)
            iv_binary = binary_data[32:32+128]
            iv = self.binary_to_bytes(iv_binary)
            
            # Extract ciphertext
            ciphertext_binary = binary_data[32+128:32+128+(ciphertext_length*8)]
            
            # Validate we have enough bits for the ciphertext
            if len(ciphertext_binary) < ciphertext_length * 8:
                print(f"Not enough data for ciphertext. Need {ciphertext_length*8} bits, but only have {len(ciphertext_binary)}.")
                return None
                
            ciphertext = self.binary_to_bytes(ciphertext_binary)
            
            print(f"IV length: {len(iv)} bytes, Ciphertext length: {len(ciphertext)} bytes")
            
            # Decrypt the message
            decrypted_message = self.decrypt_message(iv, ciphertext, password)
            
            if decrypted_message is None:
                print("Decryption failed. Possibly incorrect password.")
                
            return decrypted_message
        
        except Exception as e:
            print(f"Error during extraction: {str(e)}")
            import traceback
            traceback.print_exc()
            return None


def get_image_path():
    """
    Open a file dialog to select an image file.
    
    Returns:
        str: Path to the selected image or None if cancelled
    """
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    file_path = filedialog.askopenfilename(
        title="Select Image File",
        filetypes=[
            ("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"),
            ("All files", "*.*")
        ]
    )
    
    if file_path:
        return file_path
    return None


def main():
    print("\n=== Secure Image Steganography ===\n")
    
    # Create steganography object
    stego = SecureImageSteganography()
    
    # Ask user to upload an image
    print("Upload an image.")
    image_path = get_image_path()
    
    if not image_path:
        print("No image selected. Exiting...")
        return
    
    print(f"Selected image: {image_path}")
    
    # Ask if user wants to encrypt a message
    encrypt = input("Do you want to encrypt a text? (Y/N): ").strip().upper()
    
    if encrypt == 'Y':
        # Get the message to encrypt
        message = input("Enter secret message: ")
        
        # Get the password - using standard input instead of getpass
        password = input("Enter password: ")
        
        print("Encrypting and embedding message... Please wait.")
        
        # Encrypt and embed the message
        output_path = stego.embed_data(image_path, message, password)
        
        if output_path:
            print(f"Encrypted secret message in the uploaded image.")
            print(f"Encrypted image saved as: {output_path}")
        else:
            print("Encryption failed.")
    else:
        print("Process done.")
    
    # Ask if user wants to decrypt an image
    decrypt = input("Do you want to decrypt the image? (Y/N): ").strip().upper()
    
    if decrypt == 'Y':
        # If the user didn't encrypt an image, ask for the image to decrypt
        if encrypt != 'Y':
            print("Select the encrypted image.")
            decrypt_image_path = get_image_path()
            if not decrypt_image_path:
                print("No image selected. Exiting...")
                return
        else:
            # Use the encrypted image from earlier
            decrypt_image_path = output_path
            
        # Get the password - using standard input instead of getpass
        password = input("Enter password: ")
        
        print("Extracting and decrypting message... Please wait.")
        
        # Extract and decrypt the message
        decrypted_message = stego.extract_data(decrypt_image_path, password)
        
        if decrypted_message:
            print("Secret message is:")
            print(decrypted_message)
        else:
            print("Decryption failed. Incorrect password or no hidden message.")
    else:
        print("Process done.")


if __name__ == "__main__":
    main()