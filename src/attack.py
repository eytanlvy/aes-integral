import numpy as np
import itertools
import sys
from aes import AES

def generate_structure() -> np.ndarray:
    """
    Generate an integral attack structure with 256 distinct states.
    The first byte takes all possible values (A),
    and the other bytes are constant (C).
    """
    structure = []
    for i in range(256):
        state = np.full((4, 4), 0x42, dtype=np.uint8)
        state[0, 0] = i
        structure.append(state)
    return np.array(structure)

def run_four_rounds(aes: AES, state: np.ndarray, round_keys: list[np.ndarray]) -> np.ndarray:
    """
    Execute exactly four rounds of AES with the correct round keys.

    Args:
        aes: Instance of the AES class.
        state: Initial 4x4 state.
        round_keys: List of round keys (one per round + initial key).
    """
    state = aes.AddRoundKey(state, round_keys[0])

    # First round
    state = aes.SubBytes(state)
    state = aes.ShiftRows(state)
    state = aes.MixColumns(state)
    state = aes.AddRoundKey(state, round_keys[1])

    # Second round
    state = aes.SubBytes(state)
    state = aes.ShiftRows(state)
    state = aes.MixColumns(state)
    state = aes.AddRoundKey(state, round_keys[2])

    # Third round
    state = aes.SubBytes(state)
    state = aes.ShiftRows(state)
    state = aes.MixColumns(state)
    state = aes.AddRoundKey(state, round_keys[3])

    # Fourth round (no MixColumns)
    state = aes.SubBytes(state)
    state = aes.ShiftRows(state)
    state = aes.AddRoundKey(state, round_keys[4])

    return state

def generate_all_keys(key_candidates: list) -> list[np.ndarray]:
    """
    Génère toutes les clés possibles à partir des candidats pour chaque position.
    
    Args:
        key_candidates: Liste 4x4 où chaque élément est une liste des valeurs candidates
        
    Returns:
        list[np.ndarray]: Liste de toutes les clés possibles (matrices 4x4)
    """
    # Création d'une liste plate des candidats pour chaque position
    positions = []
    for i in range(4):
        for j in range(4):
            positions.append(key_candidates[i][j])
    
    # Génération de toutes les combinaisons possibles
    all_combinations = list(itertools.product(*positions))
    
    # Conversion de chaque combinaison en matrice 4x4
    all_keys = []
    for combination in all_combinations:
        key = np.zeros((4, 4), dtype=np.uint8)
        for idx, value in enumerate(combination):
            i, j = idx // 4, idx % 4
            key[i, j] = value
        all_keys.append(key)
    
    return all_keys

def find_key(aes: AES, ciphertexts: np.ndarray) -> list:
    """
    Implement the square attack on AES (4 rounds).

    Args:
        aes: Instance of AES.
        ciphertexts: Array of ciphertexts after 4 rounds (256, 4, 4).

    Returns:
        list: 4x4 list where each element is a list of candidate values for that position
    """
    key_candidates = [[[] for _ in range(4)] for _ in range(4)]
    print("\nStarting key recovery...")

    for i in range(4):
        for j in range(4):            
            for k in range(256):
                sum = 0

                for l in range(256):
                    sum ^= aes.inv_sbox[ciphertexts[l, i, j] ^ k]

                if sum == 0:
                    key_candidates[i][j].append(k)

            if len(key_candidates[i][j]) == 0:
                print(f"⚠️ Warning: No candidates found for position ({i},{j})")

    total_combinations = 1
    for i in range(4):
        for j in range(4):
            total_combinations *= len(key_candidates[i][j])
    
    print(f"\nNombre total de combinaisons possibles: {total_combinations}")
    
    # Génération de toutes les clés possibles
    all_keys = generate_all_keys(key_candidates)
    print(f"Nombre de clés générées: {len(all_keys)}")
    
    return all_keys

def verify_zero_sum_property(ciphertexts):
    """
    Verify the zero-sum property on the ciphertexts.

    Args:
        ciphertexts: np.array of shape (n, 4, 4) containing ciphertext states.

    Returns:
        tuple: (success, non_zero_positions)
            - success: bool indicating if the property is verified everywhere.
            - non_zero_positions: list of positions (i, j, sum) where the property fails.
    """
    print("\nVerifying the zero-sum property:")

    success = True
    non_zero_positions = []

    for i in range(4):
        for j in range(4):
            total = np.bitwise_xor.reduce(ciphertexts[:, i, j])
            if total != 0:
                success = False
                non_zero_positions.append((i, j, total))

    print("\n" + "=" * 50)
    if success:
        print("SUCCESS: The zero-sum property is verified for all bytes!")
    else:
        print(f"FAILURE: {len(non_zero_positions)} positions do not verify the property")
    print("=" * 50)
    

def run_attack(key: bytes = b"MySecretKey12345"):
    """
    Execute the integral attack on AES-128 (4 rounds).

    Args:
        key: The encryption key to use. Defaults to b"MySecretKey12345".
    """
    if len(key) != 16:
        raise ValueError("The encryption key must be exactly 16 bytes long.")

    print("Starting the integral attack on 4-round AES...")
    print("-" * 50)

    aes = AES()

    # Generate attack structure
    structure = generate_structure()
    print(f"Structure generated with {len(structure)} states")

    # Generate round keys
    round_keys = aes.key_expansion(key, Nk=4)  # AES-128
    print(f"Master Key: {key.decode('ascii')}")
    print(f"\nTotal number of round keys: {len(round_keys)}")

    # Execute four rounds on each state
    print("\nExecuting 4 rounds on each state...")
    ciphertexts = [run_four_rounds(aes, state, round_keys) for state in structure]
    ciphertexts = np.array(ciphertexts)

    # Perform key recovery
    candidates = find_key(aes, ciphertexts)
    true_key = round_keys[4]
    found = False
    for idx, possible_key in enumerate(candidates):
        if np.array_equal(possible_key, true_key):
            print(f"\n✅ Clé correcte trouvée à l'index {idx}")
            print()
            print(f"Clé trouvée:\n{possible_key}")
            print()
            print(f"Clé correcte:\n{true_key}")
            found = True
            break
    
    if not found:
        print("\n❌ La clé correcte n'a pas été trouvée parmi les candidates!")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Perform an integral attack on AES-128 (4 rounds).")
    parser.add_argument("--key", type=str, help="Specify a 16-byte encryption key (optional).", default="MySecretKey12345")

    args = parser.parse_args()
    try:
        run_attack(key=args.key.encode('utf-8'))
    except ValueError as e:
        print(f"Error: {e}")
