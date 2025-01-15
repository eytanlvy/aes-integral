from sage.all import *
import numpy as np
from typing import List

class AES:
    def __init__(self):
        self._init_constants()

    def _init_constants(self):
        """Initialize AES constants"""
        # S-box
        self.sbox = np.array([
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ], dtype=np.uint8)
        
        # Inverse S-box
        self.inv_sbox = np.array([
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        ], dtype=np.uint8)

        # Rcon (en format 32 bits)
        self.rcon = np.array([
            [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00],
            [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00],
            [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00],
            [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00],
            [0x1B, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]
        ], dtype=np.uint8)

        # Matrice MixColumns
        self.mix_columns_matrix = np.array([
            [2, 3, 1, 1],
            [1, 2, 3, 1],
            [1, 1, 2, 3],
            [3, 1, 1, 2]
        ], dtype=np.uint8)

        self.inv_mix_columns_matrix = np.array([
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E]
        ], dtype=np.uint8)

    def key_expansion(self, key: bytes, Nk: int) -> List[np.ndarray]:
        """
        Generates subkeys from the master key
        Nk: key size in 32-bit words (4 for AES-128, 6 for AES-192, 8 for AES-256)
        """
        Nr = Nk + 6  # Number of rounds
        W = np.zeros((4 * (Nr + 1), 4), dtype=np.uint8)
        
        # Copy master key
        key_array = np.frombuffer(key, dtype=np.uint8).reshape(-1, 4)
        W[:Nk] = key_array
        
        for i in range(Nk, 4 * (Nr + 1)):
            temp = W[i-1].copy()
            
            if i % Nk == 0:
                # Rotation
                temp = np.roll(temp, -1)
                # SubBytes
                for j in range(4):
                    temp[j] = self.sbox[temp[j]]
                # XOR with Rcon
                temp ^= self.rcon[i//Nk - 1]
            elif Nk > 6 and i % Nk == 4:
                # AES-256: Additional SubBytes
                for j in range(4):
                    temp[j] = self.sbox[temp[j]]
                    
            W[i] = W[i-Nk] ^ temp
            
        # Convert to 4x4 matrices for each round
        return [W[i:i+4].T for i in range(0, len(W), 4)]

    def AddRoundKey(self, state: np.ndarray, round_key: np.ndarray) -> np.ndarray:
        return state ^ round_key

    def SubBytes(self, state: np.ndarray) -> np.ndarray:
        result = np.zeros_like(state)
        for i in range(4):
            for j in range(4):
                result[i, j] = self.sbox[state[i, j]]
        return result
    
    def InvSubBytes(self, state: np.ndarray) -> np.ndarray:
        result = np.zeros_like(state)
        for i in range(4):
            for j in range(4):
                result[i, j] = self.inv_sbox[state[i, j]]
        return result

    def ShiftRows(self, state: np.ndarray) -> np.ndarray:
        result = np.zeros_like(state)
        result[0] = state[0]  # First row doesn't move
        result[1] = np.roll(state[1], -1)  # Shift 1 position left
        result[2] = np.roll(state[2], -2)  # Shift 2 positions left
        result[3] = np.roll(state[3], -3)  # Shift 3 positions left
        return result
    
    def InvShiftRows(self, state: np.ndarray) -> np.ndarray:
        result = np.zeros_like(state)
        for i in range(4):
            result[i] = np.roll(state[i], i)
        return result

    def gmul(self, a: int, b: int) -> int:
        """Performs multiplication in GF(2^8) using AES polynomial."""
        p = 0
        for _ in range(8):
            if b & 1:  # If LSB of b is 1
                p ^= a
            high_bit_set = a & 0x80  # Check if MSB of a is 1
            a = (a << 1) & 0xFF  # Shift a left (keep 8 bits)
            if high_bit_set:
                a ^= 0x1B  # Apply AES irreducible polynomial
            b >>= 1  # Shift b right
        return p

    def MixColumns(self, state: np.ndarray) -> np.ndarray:
        """Applies MixColumns transformation to a 4x4 state matrix."""
        assert state.shape == (4, 4), "State must be a 4x4 matrix."
        result = np.zeros((4, 4), dtype=np.uint8)

        for c in range(4):  # For each column
            for i in range(4):  # For each row in column
                result[i, c] = 0
                for j in range(4):
                    result[i, c] ^= self.gmul(self.mix_columns_matrix[i, j], state[j, c])

        return result
    
    def InvMixColumns(self, state: np.ndarray) -> np.ndarray:
        result = np.zeros((4, 4), dtype=np.uint8)
        for c in range(4):
            for i in range(4):
                result[i, c] = 0
                for j in range(4):
                    result[i, c] ^= self.gmul(self.inv_mix_columns_matrix[i, j], state[j, c])
        return result
    
    def pad_message(self, message: bytes) -> bytes:
        """PKCS#7 padding"""
        pad_len = 16 - (len(message) % 16)
        return message + bytes([pad_len] * pad_len)
    
    def unpad(self, padded_data: bytes) -> bytes:
        """Remove PKCS#7 padding"""
        pad_len = padded_data[-1]
        return padded_data[:-pad_len]

    def encrypt(self, message: bytes, key: bytes) -> bytes:
        """
        Encrypts a message with AES
        - message: message to encrypt
        - key: key of 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
        """
        # Determine AES version based on key size
        key_size = len(key)
        if key_size == 16:
            Nk = 4  # AES-128
        elif key_size == 24:
            Nk = 6  # AES-192
        elif key_size == 32:
            Nk = 8  # AES-256
        else:
            raise ValueError("Invalid key size. Must be 16, 24, or 32 bytes.")

        # Padding
        padded_message = self.pad_message(message)
        
        # Generate subkeys
        round_keys = self.key_expansion(key, Nk)
        
        # Block encryption
        ciphertext = b''
        for i in range(0, len(padded_message), 16):
            block = padded_message[i:i+16]
            state = np.frombuffer(block, dtype=np.uint8).reshape(4, 4)
            
            # Initial AddRoundKey
            state = self.AddRoundKey(state, round_keys[0])
            
            # Main rounds
            for j in range(1, len(round_keys) - 1):
                state = self.SubBytes(state)
                state = self.ShiftRows(state)
                state = self.MixColumns(state)
                state = self.AddRoundKey(state, round_keys[j])
            
            # Final round (without MixColumns)
            state = self.SubBytes(state)
            state = self.ShiftRows(state)
            state = self.AddRoundKey(state, round_keys[-1])
            
            ciphertext += state.tobytes()
            
        return ciphertext
    
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """AES Decryption"""
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext must be a multiple of 16 bytes")
            
        # Determine AES version based on key size
        key_size = len(key)
        if key_size == 16:
            Nk = 4  # AES-128
        elif key_size == 24:
            Nk = 6  # AES-192
        elif key_size == 32:
            Nk = 8  # AES-256
        else:
            raise ValueError("Invalid key size. Must be 16, 24, or 32 bytes.")
            
        # Key schedule
        round_keys = self.key_expansion(key, Nk)
        
        # Decryption
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            state = np.frombuffer(block, dtype=np.uint8).reshape(4, 4)
            
            state = self.AddRoundKey(state, round_keys[-1])
            
            for j in range(len(round_keys)-2, 0, -1):
                state = self.InvShiftRows(state)
                state = self.InvSubBytes(state)
                state = self.AddRoundKey(state, round_keys[j])
                state = self.InvMixColumns(state)
            
            state = self.InvShiftRows(state)
            state = self.InvSubBytes(state)
            state = self.AddRoundKey(state, round_keys[0])
            
            plaintext += state.tobytes()
            
        # Remove padding
        return self.unpad(plaintext)