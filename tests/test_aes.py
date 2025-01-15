import numpy as np
import sys
sys.path.append('.')  # Instead of '../'
from src.aes import AES

def test_shiftrows(aes, state):
    print("Testing ShiftRows...")
    result = aes.ShiftRows(state)

    assert np.array_equal(result[0], state[0]), "Error: first row modified"
    assert result[1, 0] == state[1, 1], "Error: incorrect shift for row 2"
    assert result[2, 0] == state[2, 2], "Error: incorrect shift for row 3"
    assert result[3, 0] == state[3, 3], "Error: incorrect shift for row 4"

    print("OK!")

def test_addroundkey(aes, state, round_key):
    print("Testing AddRoundKey...")
    result = aes.AddRoundKey(state, round_key)
    expected = state ^ round_key
    assert np.array_equal(result, expected), "Error: incorrect XOR operation"
    print("OK!")

def test_subbytes(aes, state):
    print("Testing SubBytes...")
    result = aes.SubBytes(state)
    assert result[0, 0] == aes.sbox[0x00], "Error: incorrect substitution for 0x00"
    assert result[0, 1] == aes.sbox[0x01], "Error: incorrect substitution for 0x01"
    print("OK!")

def test_encryption():
    print("Testing Encryption/Decryption...")

    aes = AES()
    
    test_cases = [
        # Test case 1: Basic test with padding needed
        {
            "message": b"Hello, AES world!",
            "key": b"SuperSecretKey12",  # 16-byte key (AES-128)
            "description": "Basic AES-128 with padding"
        },
        # Test case 2: Exact block size (16 bytes)
        {
            "message": b"ExactBlock16Bytes",
            "key": b"VerySecretKey1234567890+",  # 24-byte key (AES-192)
            "description": "AES-192 with exact block size"
        },
        # Test case 3: Multiple blocks with padding
        {
            "message": b"This is a longer message that will require multiple blocks and padding!",
            "key": b"Ultra-Secret-Key-For-Maximum-123",  # 32-byte key (AES-256)
            "description": "AES-256 with multiple blocks"
        },
        # Test case 4: Special characters
        {
            "message": b"Special @#$%^&* chars \x00\x01\xff",
            "key": b"SpecialKey123456",  # 16-byte key
            "description": "Special characters test"
        },
        # Test case 5: Empty message
        {
            "message": b"",
            "key": b"EmptyMsgTestKey!",  # 16-byte key
            "description": "Empty message test"
        },
        # Test case 6: One byte message
        {
            "message": b"X",
            "key": b"SingleByteKey123",  # 16-byte key
            "description": "Single byte message"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        message = test_case["message"]
        key = test_case["key"]
        description = test_case["description"]
        
        print(f"\nTest {i}: {description}")
        print(f"Message length: {len(message)} bytes")
        print(f"Key length: {len(key)} bytes")
        
        try:
            # Encryption
            ciphertext = aes.encrypt(message, key)
            print(f"Ciphertext length: {len(ciphertext)} bytes")
            
            # Decryption
            decrypted = aes.decrypt(ciphertext, key)
            
            # Verification
            assert message == decrypted, (
                f"Failed: decrypted message doesn't match original\n"
                f"Original : {message}\n"
                f"Decrypted: {decrypted}"
            )
            print("✅ Success")
            
        except Exception as e:
            print(f"❌ Failed: {str(e)}")
            raise
    
    # Additional negative test cases
    print("\nTesting error cases...")
    
    try:
        # Invalid key size
        aes.encrypt(b"Test", b"TooShortKey")
        print("❌ Failed: Should have rejected invalid key size")
    except ValueError as e:
        print("✅ Successfully caught invalid key size")
    
    try:
        # Invalid ciphertext length
        aes.decrypt(b"Invalid length", b"ValidKey1234567890")
        print("❌ Failed: Should have rejected invalid ciphertext length")
    except ValueError as e:
        print("✅ Successfully caught invalid ciphertext length")
    
    print("\nAll encryption tests completed!")

def run_tests():
    print("Starting tests...")
    print("-" * 40)

    # Initialization
    aes = AES()
    state = np.array([
        [0x00, 0x01, 0x02, 0x03],
        [0x04, 0x05, 0x06, 0x07],
        [0x08, 0x09, 0x0a, 0x0b],
        [0x0c, 0x0d, 0x0e, 0x0f]
    ], dtype=np.uint8)

    round_key = np.array([
        [0x00, 0x01, 0x02, 0x03],
        [0x04, 0x05, 0x06, 0x07],
        [0x08, 0x09, 0x0a, 0x0b],
        [0x0c, 0x0d, 0x0e, 0x0f]
    ], dtype=np.uint8)

    plaintext = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'

    # Simplified round key generation
    round_keys = [round_key for _ in range(11)]

    # Running tests
    try:
        test_shiftrows(aes, state)
        test_addroundkey(aes, state, round_key)
        test_subbytes(aes, state)
        test_encryption()
        print("-" * 40)
        print("All tests passed!")
    except AssertionError as e:
        print("❌ FAIL:", str(e))
    except Exception as e:
        print("❌ UNEXPECTED ERROR:", str(e))

if __name__ == '__main__':
    run_tests()