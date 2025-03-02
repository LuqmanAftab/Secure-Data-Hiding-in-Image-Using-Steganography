# Secure Data Hiding in Image Using Steganography

A Python implementation of secure image steganography that combines AES encryption with LSB (Least Significant Bit) steganography for hiding sensitive information within images.

## Introduction

This project implements a robust method to hide confidential data within digital images. The implementation follows these key steps:

1. **Encryption**: The secret message is first encrypted using the Advanced Encryption Standard (AES) in CBC mode with a secure 256-bit key.
2. **Binary Conversion**: The encrypted data is converted into binary format.
3. **LSB Embedding**: The binary data is embedded into the least significant bits of the image pixels, making the modifications imperceptible to the human eye.
4. **Extraction & Decryption**: For retrieving the hidden message, the process is reversed - the LSB data is extracted, converted back to bytes, and decrypted using the same AES key.

This combination of cryptography and steganography provides two layers of security: even if someone suspects steganography is used, they would still need the encryption key to access the actual message.

## Features

- Strong AES-256 encryption in CBC mode with random initialization vector (IV)
- LSB steganography with minimal visual impact on carrier images
- Support for color (RGB) images in common formats (PNG, BMP, JPEG, etc.)
- Command-line interface for easy integration
- Automatic key management
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
- Pip (Python package installer)

### Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/secure-image-steganography.git
   cd secure-image-steganography
   ```

2. Create a virtual environment (optional but recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required packages:
   ```
   pip install numpy Pillow pycryptodome
   ```

### Usage

#### Hiding a Message

To hide a message in an image:

```
python steganography.py hide -i input_image.png -m "Your secret message" -o output_image.png
```

This will:
- Generate a random encryption key
- Encrypt the message using AES
- Hide the encrypted data in the image
- Save the output image
- Save the encryption key to a file (required for later extraction)

#### Extracting a Message

To extract a hidden message from an image:

```
python steganography.py extract -i stego_image.png -k key_file.txt
```

This will:
- Load the encryption key
- Extract the hidden data from the image
- Decrypt the message
- Display the original message

## Security Considerations

- Always keep the encryption key secure and separate from the stego image
- Use lossless image formats like PNG to prevent data loss during saving
- For maximum security, use the program on a secure, offline system
- The stego image should not be compressed or modified after the data is embedded

## Limitations

- The carrier image must have sufficient capacity to store the encrypted message
- Works best with lossless image formats (PNG, BMP) rather than lossy formats (JPEG)
- The program does not hide the fact that steganography is being used (only the content is protected)

## Future Enhancements

- Support for other steganography techniques (DCT, wavelet-based)
- Multiple encryption options
- Password-based key derivation
- Image quality analysis tools
- Spread-spectrum techniques for increased robustness

## License

This project is available under the MIT License.

## Contributor

- Gudur Luqman Aftab

---

*Note: This project is intended for educational purposes and legitimate security applications only. Always respect privacy laws and regulations when using steganography and encryption technologies.*
