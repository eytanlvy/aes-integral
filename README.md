# aes-integral
This project implements the Advanced Encryption Standard (AES) algorithm in Python and demonstrates an integral cryptanalysis attack on a 4-round version of AES-128. 

## Features

- Full implementation of AES-128, AES-192, and AES-256
- Support for key expansion, encryption, and decryption
- PKCS#7 padding implementation
- Integral attack demonstration on 4-round AES
- Comprehensive test suite

## Dependencies

- Python 3.x
- NumPy
- SageMath

## Installation

1. Clone the repository
2. Install the required dependencies:
```bash
pip install numpy sage-math
```

## Usage
### Running the AES Implementation
```python
from aes import AES

# Initialize AES
aes = AES()

# Example with AES-128
key = b"MySecretKey12345"  # 16 bytes for AES-128
message = b"Hello, World!"

# Encrypt
ciphertext = aes.encrypt(message, key)

# Decrypt
plaintext = aes.decrypt(ciphertext, key)
```

### Running the Integral Attack
```bash
# Run with default key
python attack.py

# Run with custom key (must be 16 bytes)
python attack.py --key "YourCustomKey1234"
```
## Security Note
This implementation is for educational purposes and should not be used in production environments.

## License
This project is open source and available under the MIT License.

