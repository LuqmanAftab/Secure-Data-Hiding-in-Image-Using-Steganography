# Secure Data Hiding in Image Using Steganography

A Python implementation of secure image steganography that combines AES encryption with LSB (Least Significant Bit) steganography for hiding sensitive information within images.

## Introduction

This project implements a robust method to conceal confidential data within digital images. The implementation follows these key steps:

1. **Encryption**: The secret message is encrypted using Advanced Encryption Standard (AES) in CBC mode with a secure 256-bit key.
2. **Binary Conversion**: The encrypted data is converted into binary format.
3. **LSB Embedding**: The binary data is embedded into the least significant bits of the image pixels, making the modifications imperceptible to the human eye.
4. **Extraction & Decryption**: To retrieve the hidden message, the process is reversed—extracting the LSB data, converting it back to bytes, and decrypting it using the same AES key.

This combination of cryptography and steganography provides two layers of security: even if someone suspects steganography is being used, they would still need the encryption key to access the actual message.

## Features

- Strong AES-256 encryption in CBC mode with a randomly generated initialization vector (IV)
- LSB steganography with minimal visual impact on carrier images
- Support for color (RGB) images in common formats (PNG, BMP, JPEG, etc.)
- Command-line interface for easy integration
- Automatic key management for encryption and decryption
- Validation to ensure the carrier image has sufficient capacity

## Resources Used

- **Python 3.7+**: Core programming language
- **NumPy**: For efficient image array manipulation
- **Pillow**: For image processing
- **PyCryptodome**: For AES encryption/decryption
- **Argparse**: For command-line argument parsing

## Setup Instructions

### Prerequisites

- Python 3.7 or higher
- Pip (Python package manager)

### Installation

1. Clone this repository:
   ```sh
   git clone https://github.com/LuqmanAftab/Secure-Data-Hiding-in-Image-Using-Steganography.git
   ```

2. Create a virtual environment (optional but recommended):
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```sh
   pip install numpy Pillow pycryptodome
   ```

### Usage

#### Hiding a Message

To hide a message inside an image:

```sh
python Steganography_main.py
```

**This will:**
- Upload image and enter secret text.
- Provide a password to securely hide text messages within images using steganography.
- Encrypt messages using AES (CBC mode) before embedding them into images.
- Convert encrypted data into a binary format to embed within image pixels' least significant bits (LSBs).

#### Extracting a Message

Extracting the hidden message from an image involves:

- Extract hidden messages from stego images and decrypt them with a password.
- Utilize OpenCV and PIL for image processing.
- Offer a user-friendly interface using Tkinter to select images for embedding and extraction.
- Ensure data security by requiring a password to encrypt and decrypt messages.
- Handle errors like incorrect passwords, insufficient image size, and invalid decryption attempts.

## Security Considerations

- Always keep the encryption key secure and separate from the stego image.
- For maximum security, run the program in a secure, offline environment.
- The stego image should not be compressed or modified after embedding the data.

## Limitations

- The carrier image must have sufficient capacity to store the encrypted message.
- Works best with lossless image formats (PNG, BMP) rather than lossy formats (JPEG).
- This method does not conceal the presence of steganography, only the hidden content.

## Future Enhancements

- Support for alternative steganography techniques (DCT, wavelet-based methods).
- Additional encryption algorithms beyond AES-256.
- Password-based key derivation for added security.
- Image quality analysis tools to detect distortions.
- Spread-spectrum techniques for improved robustness against detection.

## License

This project is licensed under the MIT License.

## Contributor

- **Gudur Luqman Aftab**

