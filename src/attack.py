import numpy as np
import itertools
import sys
from typing import List
from aes import AES

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
    
    
    # Génération de toutes les clés possibles
    all_keys = generate_all_keys(key_candidates)
    
    return all_keys

def generate_structure(constant_value: int) -> np.ndarray:
    """
    Generate an integral attack structure with 256 distinct states.
    The first byte takes all possible values (A),
    and the other bytes are constant (C).
    
    Args:
        constant_value: The constant value to use for non-active bytes
    """
    structure = []
    for i in range(256):
        state = np.full((4, 4), constant_value, dtype=np.uint8)
        state[0, 0] = i
        structure.append(state)
    return np.array(structure)

def find_intersection_of_candidate_keys(key_lists: List[List[np.ndarray]]) -> List[np.ndarray]:
    """
    Find the intersection of multiple lists of candidate keys.
    
    Args:
        key_lists: List of lists of candidate keys from different attacks
        
    Returns:
        List of keys that appear in all lists
    """
    if not key_lists:
        return []
        
    # Convert numpy arrays to tuples for comparison
    def array_to_tuple(arr):
        return tuple(map(tuple, arr))
    
    # Convert first list's arrays to tuples
    common_keys_tuples = set(array_to_tuple(key) for key in key_lists[0])
    
    # Find intersection with remaining lists
    for key_list in key_lists[1:]:
        current_keys = set(array_to_tuple(key) for key in key_list)
        common_keys_tuples = common_keys_tuples.intersection(current_keys)
    
    # Convert tuples back to numpy arrays
    return [np.array(key) for key in common_keys_tuples]

def run_attack(aes: AES, constant_values: List[int], round_keys: List[np.ndarray]) -> tuple[np.ndarray, bool]:
    """
    Run multiple attacks with different constant values and find the intersection
    of candidate keys.
    
    Args:
        aes: Instance of AES
        constant_values: List of constant values to use in different attacks
        round_keys: List of round keys
        
    Returns:
        tuple: (final_key, success) where success is True if the key matches round_keys[4]
    """
    true_key = round_keys[4]
    all_candidate_lists = []
    
    for idx, constant in enumerate(constant_values, 1):
        print(f"\nRunning attack #{idx} with constant value 0x{constant:02x}")
        
        structure = generate_structure(constant)
        ciphertexts = [run_four_rounds(aes, state, round_keys) for state in structure]
        ciphertexts = np.array(ciphertexts)
        
        candidates = find_key(aes, ciphertexts)
        print(f"Found {len(candidates)} candidate keys")
        
        all_candidate_lists.append(candidates)
        common_keys = find_intersection_of_candidate_keys(all_candidate_lists)
        print(f"Number of keys in common so far: {len(common_keys)}")
        
        if len(common_keys) == 1:
            return common_keys[0], np.array_equal(common_keys[0], true_key)
        elif len(common_keys) == 0:
            return None, False
    
    return None, False

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description="Perform an integral attack on AES-128 (4 rounds).")
    parser.add_argument("--key", type=str, help="Specify a 16-byte encryption key (optional).", 
                       default="MySecretKey12345")
    args = parser.parse_args()

    try:
        key = args.key.encode('utf-8')
        if len(key) != 16:
            raise ValueError("The encryption key must be exactly 16 bytes long.")

        constant_values = [0x42, 0x13, 0x37, 0x55, 0xAA]
        print("Starting refined integral attack on 4-round AES...")
        print(f"Using constant values: {', '.join(f'0x{x:02x}' for x in constant_values)}")
        
        aes = AES()
        round_keys = aes.key_expansion(key, Nk=4)
        final_key, success = run_attack(aes, constant_values, round_keys)
        
        if final_key is not None:
            print("\nKey found!")
            if success:
                print("✅ The key is correct!")
            else:
                print("❌ The key is incorrect!")
            print("\nExpected:")
            print(round_keys[4])
            print("\nFound:")
            print(final_key)
        else:
            print("\n❌ Attack failed - no key found")
            
    except ValueError as e:
        print(f"Error: {e}")