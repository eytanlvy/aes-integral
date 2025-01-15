import numpy as np
import sys
sys.path.append('.')  # Au lieu de '../'
from aes import AES

def test_shiftrows(aes, state):
    print("Test ShiftRows...")
    result = aes.ShiftRows(state)

    assert np.array_equal(result[0], state[0]), "Erreur: première ligne modifiée"
    assert result[1, 0] == state[1, 1], "Erreur: décalage ligne 2 incorrect"
    assert result[2, 0] == state[2, 2], "Erreur: décalage ligne 3 incorrect"
    assert result[3, 0] == state[3, 3], "Erreur: décalage ligne 4 incorrect"

    print("OK!")

def test_addroundkey(aes, state, round_key):
    print("Test AddRoundKey...")
    result = aes.AddRoundKey(state, round_key)
    expected = state ^ round_key
    assert np.array_equal(result, expected), "Erreur: XOR incorrect"
    print("OK!")

def test_subbytes(aes, state):
    print("Test SubBytes...")
    result = aes.SubBytes(state)
    assert result[0, 0] == aes.sbox[0x00], "Erreur: substitution de 0x00 incorrecte"
    assert result[0, 1] == aes.sbox[0x01], "Erreur: substitution de 0x01 incorrecte"
    print("OK!")

def test_mixcolumns(aes, state):
    print("Test MixColumns...")
    result = aes.MixColumns(state)
    print("State avant:")
    print(state)
    print("State après:")
    print(result)
    print("OK!")

def test_encryption():
    print("Test Encryption/Decryption...")

    aes = AES()
    
    # Message et clé de test
    message = b"Hello, AES world!"
    key = b"MySecretKey12345"  # Clé de 16 octets pour AES-128
    
    # Chiffrement
    ciphertext = aes.encrypt(message, key)
    
    # Déchiffrement
    decrypted = aes.decrypt(ciphertext, key)
    
    # Vérification
    assert message == decrypted, f"Échec: le message déchiffré ne correspond pas à l'original\nOriginal: {message}\nDéchiffré: {decrypted}"
    
    print("Test réussi!")

def run_tests():
    print("Démarrage des tests...")
    print("-" * 40)

    # Initialisation
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

    # Génération simplifiée des clés de round
    round_keys = [round_key for _ in range(11)]

    # Exécution des tests
    try:
        test_shiftrows(aes, state)
        test_addroundkey(aes, state, round_key)
        test_subbytes(aes, state)
        test_mixcolumns(aes, state)
        test_encryption()
        print("-" * 40)
        print("Tous les tests ont réussi!")
    except AssertionError as e:
        print("❌ ECHEC:", str(e))
    except Exception as e:
        print("❌ ERREUR INATTENDUE:", str(e))

if __name__ == '__main__':
    run_tests()
