from collections import defaultdict
import math
from typing import Tuple, Dict
from KDF_chain import kdf, generate_aes128_key

def generate_tree(n: int) -> Tuple[Dict[str, bytes], Dict[str, bytes]]:
    """Generate the tree of n keys."""
    l = math.ceil(math.log2(n))
    dk = defaultdict(bytes)
    sek = defaultdict(bytes)
    dk[''] = generate_aes128_key()
    stack = [('', 0)]  # Stack holds tuples of (key, depth)
    
    while stack:
        parent_key, depth = stack.pop()
        parent = dk[parent_key]

        direction = 0 if parent_key == '' or parent_key[-1] == '0' else 1
        
        if depth == l - 1:
            """Determine if the keys are leaves."""
            sek[parent_key + '0'], sek[parent_key + '1'] = kdf(parent, direction)
        else:
            dk[parent_key + '0'], dk[parent_key + '1'] = kdf(parent, direction)
            stack.append((parent_key + '1', depth + 1))
            stack.append((parent_key + '0', depth + 1))
    
    return dk, sek

def generate_kdft_keys(epochs, dk, sek, n):
    """Generate the epoch keys for a list of epochs."""
    l = math.ceil(math.log2(n))
    epochs.sort()
    if epochs[0] < 0 or epochs[-1] >= n:
        raise ValueError("Invalid epochs")
    epoch_keys = defaultdict(bytes)
    for e in epochs:
        epoch_keys[f'{e:0{l}b}'] = sek[f'{e:0{l}b}']
    
    found_parent = True
    while found_parent:
        found_parent = False
        keys = sorted(epoch_keys.keys())
        i = 0
        while i < len(keys) - 1:
            key1 = keys[i]
            key2 = keys[i + 1]
            if len(key1) != len(key2):
                i += 1
                continue
            length = len(key1) - 1
            if key1[:length] == key2[:length]:
                epoch_keys.pop(key2)
                epoch_keys.pop(key1)
                epoch_keys[key1[:length]] = dk[key1[:length]]
                found_parent = True
            i += 1
    return epoch_keys

if __name__ == '__main__':
    """Example of generating a tree and epoch keys."""
    n = 8
    epochs = [1,2]
    dk, sek = generate_tree(n)
    
    dk_hex = {k: v.hex() for k, v in dk.items()}
    sek_hex = {k: v.hex() for k, v in sek.items()}
    
    print("DK (Intermediate Keys):")
    for k, v in dk_hex.items():
        print(f"{k}: {v}")
    
    print("\nSEK (Leaf Keys):")
    for k, v in sek_hex.items():
        print(f"{k}: {v}")
        
    epoch_keys = generate_kdft_keys(epochs, dk, sek, n)
    print("\nEpoch Keys:")
    for k in sorted(epoch_keys.keys()):
        print(f"{k}: {epoch_keys[k].hex()}")