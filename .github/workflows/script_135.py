import time
import math
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point, PointJacobi
from ecdsa.util import string_to_number
from multiprocessing import Pool, cpu_count

# Constants
P = SECP256k1.curve.p()  # The prime for secp256k1 curve
G = SECP256k1.generator  # The generator of secp256k1 curve
N = SECP256k1.order  # The order of the generator

# Function to convert a point to affine coordinates
def to_affine(point):
    """
    Converts a PointJacobi to Point if needed, otherwise returns the point unchanged.
    """
    if isinstance(point, PointJacobi):
        return point.to_affine()
    return point

# Function to decode compressed public key
def decode_compressed_pubkey(pubkey_bytes):
    """
    Decodes a compressed public key into an elliptic curve point.
    """
    if len(pubkey_bytes) != 33:
        raise ValueError("Compressed public key must be 33 bytes long.")
    
    x = int.from_bytes(pubkey_bytes[1:], 'big')
    y_squared = (x**3 + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    
    # Adjust y based on compression byte
    if (pubkey_bytes[0] == 0x02 and y % 2 != 0) or (pubkey_bytes[0] == 0x03 and y % 2 == 0):
        y = P - y
    
    # Verify point on curve
    if not SECP256k1.curve.contains_point(x, y):
        raise ValueError("Decoded point does not lie on the curve.")
    
    return Point(SECP256k1.curve, x, y)

# Baby-Step Giant-Step algorithm
def bsgs_algorithm(target_point, start, end):
    """
    Finds a private key in the range [start, end) using Baby-Step Giant-Step algorithm.
    """
    m = int(math.sqrt(end - start)) + 1  # Step size (square root of the range)
    baby_steps = {}
    current_point = G  # Start from G
    
    print("Computing baby steps...")
    for i in range(m):
        baby_steps[(current_point.x(), current_point.y())] = i
        current_point += G  # Move to the next step
    
    # Compute the giant step
    g_m = to_affine(G * m)  # Convert to affine coordinates
    current_point = to_affine(target_point)  # Ensure target_point is in affine coordinates

    print("Searching giant steps...")
    for j in range(m):
        if (current_point.x(), current_point.y()) in baby_steps:
            # Found a match, calculate the private key
            i = baby_steps[(current_point.x(), current_point.y())]
            return j * m + i
        
        # Negate g_m and add to current_point
        g_m_negated = -g_m  # Negate the point
        current_point = to_affine(current_point + g_m_negated)  # Add negated point
    
    return None  # Private key not found

# Function to search using BSGS in parallel
def bsgs_parallel(target_point, start, end, num_chunks=10):
    """
    Uses BSGS in parallel by splitting the range into chunks.
    """
    print(f"Splitting the range [{start}, {end}] into {num_chunks} chunks...")
    
    total_keys = end - start
    chunk_size = total_keys // num_chunks
    ranges = [(start + i * chunk_size, start + (i + 1) * chunk_size, target_point) for i in range(num_chunks)]
    ranges[-1] = (ranges[-1][0], end, target_point)  # Ensure last chunk includes all keys

    start_time = time.time()
    with Pool(processes=min(num_chunks, cpu_count())) as pool:
        results = pool.map(bsgs_algorithm_wrapper, ranges)
    
    for result in results:
        if result is not None:
            elapsed_time = time.time() - start_time
            print(f"Private Key Found: {result}")
            print(f"Time Taken: {elapsed_time:.2f} seconds")
            return result
    
    elapsed_time = time.time() - start_time
    print(f"Private key not found in range. Total time: {elapsed_time:.2f} seconds.")
    return None

def bsgs_algorithm_wrapper(args):
    """
    Wrapper for multiprocessing BSGS calls.
    """
    start, end, target_point = args
    return bsgs_algorithm(target_point, start, end)

# Main function to solve Bitcoin puzzle
def solve_bitcoin_puzzle(public_key_hex, start, end):
    """
    Solves the puzzle by searching for the private key in the given range.
    """
    public_key_bytes = bytes.fromhex(public_key_hex)
    target_point = decode_compressed_pubkey(public_key_bytes)
    
    # Validate the target point
    assert SECP256k1.curve.contains_point(target_point.x(), target_point.y()), \
        "The target point is invalid or not on the curve."
    print(f"Decoded Public Key Point: ({target_point.x()}, {target_point.y()})")
    
    # Call function to find the private key using BSGS in parallel
    num_chunks = 10  # Adjust as needed or leave as default
    private_key = bsgs_parallel(target_point, start, end, num_chunks)
    
    if private_key is not None:
        print(f"Private Key Found: {private_key}")
    else:
        print("Private key not found.")
    return private_key

if __name__ == "__main__":
    # Puzzle constants
    public_key_hex = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
    start_decimal = 2**134  # Start with a small range for testing
    end_decimal = 2**135    # End range
    
    # Solve the puzzle
    solve_bitcoin_puzzle(public_key_hex, start_decimal, end_decimal)