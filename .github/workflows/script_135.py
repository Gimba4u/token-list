import os
import random
import hashlib
import multiprocessing
from multiprocessing import Manager, Process, Lock
from ecdsa import SECP256k1, SigningKey, VerifyingKey
import binascii
import logging
from math import ceil, sqrt
from queue import Empty
import signal
import argparse

# 🎯 Target Public Key and Target address (Replace with the actual public key and address you're searching for)
TARGET_PUBLIC_KEY = "02145D2611C823A396EF6712CE0F712F09B9B4F3135E3E0AA3230FB9B6D08D1E16"
TARGET_ADDRESS = "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"

# 🔑 Key Range
START_KEY = 0x4000000000000000000000000000000000
END_KEY = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # Customizable END_KEY

# 🏇 Kangaroo Parameters
PROCESS_COUNT = os.cpu_count() or 8  # Number of Wild Kangaroo Processes, defaults to CPU count
JUMP_TABLE_SIZE = 512  # Number of predefined jumps
JUMP_RANGE = (2**16, 2**22)  # Fine-tuned Jump sizes (65536 to 4194304)

# 📁 Resume & Output Files
FOUND_KEYS_FILE = "found_keys.txt"
PROGRESS_FILE = "progress.txt"

# 📌 Secp256k1 Curve
curve = SECP256k1.curve
G = SECP256k1.generator

# 🔄 Jump Table Precomputation
JUMP_TABLE = [random.randint(*JUMP_RANGE) for _ in range(JUMP_TABLE_SIZE)]
JUMP_TABLE.sort(reverse=True)  # Favor larger jumps first

# Configure Logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s', handlers=[logging.StreamHandler(), logging.FileHandler("kangaroo_search.log")])

# 🛠 Utility Functions
def hex_to_pubkey(hex_str):
    """Convert a hex string to an elliptic curve point (public key)."""
    try:
        if hex_str[:2] not in ("02", "03"):
            raise ValueError("Public key should start with 02 or 03 for compressed keys.")

        pubkey_bytes = binascii.unhexlify(hex_str)
        vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)
        pubkey_point = vk.pubkey.point
        return (int(pubkey_point.x()), int(pubkey_point.y()))

    except Exception as e:
        logging.error(f"Error converting hex to pubkey: {e}")
        return None

def private_to_public(private_key):
    """Compute public key from private key and return hashable (x, y) tuple."""
    try:
        pubkey = (private_key * G).to_affine()
        return (int(pubkey.x()), int(pubkey.y()))
    except Exception as e:
        logging.error(f"Error computing public key from private key: {e}")
        return None

def private_to_compressed_public_key(private_key_hex):
    """Convert a private key to its compressed public key."""
    private_key_hex = private_key_hex.zfill(64)
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    vk = sk.verifying_key
    return vk.to_string("compressed").hex()

def save_progress(current_key, lock):
    """Save the current key to a file for resuming later."""
    with lock:
        try:
            with open(PROGRESS_FILE, "w") as f:
                f.write(f"{hex(current_key)}\n")
        except Exception as e:
            logging.error(f"Error saving progress: {e}")

def load_progress():
    """Load the last saved key from the file."""
    if os.path.exists(PROGRESS_FILE):
        try:
            with open(PROGRESS_FILE, "r") as f:
                return int(f.read().strip(), 16)
        except Exception as e:
            logging.error(f"Error loading progress: {e}")
    return None

# 🏁 Function to print END_KEY before search starts
def print_end_key():
    """Print the END_KEY before the search begins for verification."""
    logging.info(f"END_KEY: {hex(END_KEY)}")

# 🍼 Baby-Step Giant-Step (BSGS) Algorithm
def bsgs(target_pubkey, start_key, end_key, result_queue):
    """Baby-Step Giant-Step algorithm for discrete logarithm problem."""
    m = ceil(sqrt(end_key - start_key))
    baby_steps = {}
    giant_stride = m * G

    logging.info(f"BSGS: Starting with m={m}, giant_stride={giant_stride}")

    # Baby steps: precompute (i * G) for i in range(m)
    for i in range(m):
        point = (start_key + i) * G
        baby_steps[(int(point.x()), int(point.y()))] = start_key + i

    # Giant steps: compute (target_pubkey - j * m * G) and check against baby steps
    for j in range(m):
        candidate_point = target_pubkey - j * giant_stride
        candidate_tuple = (int(candidate_point.x()), int(candidate_point.y()))
        
        if candidate_tuple in baby_steps:
            logging.info(f"BSGS: Match found at j={j}, i={baby_steps[candidate_tuple]}")
            result_queue.put(baby_steps[candidate_tuple] + j * m)
            return

    logging.info("BSGS: No match found.")

# 🏇 Tame Kangaroo (Backward Search from Target Public Key)
def tame_kangaroo_search(tame_points, tame_points_queue, end_key, lock, result_queue):
    """Parallelized Tame Kangaroo using multiprocessing for faster point collection with heuristic pruning."""
    target_pubkey = hex_to_pubkey(TARGET_PUBLIC_KEY)
    if not target_pubkey:
        logging.error("Invalid target public key format!")
        return None

    private_key = load_progress() or end_key
    step_size = random.choice(JUMP_TABLE)

    logging.info(f"Tame Kangaroo Started from {TARGET_PUBLIC_KEY}...")

    while private_key > START_KEY:
        public_key = private_to_public(private_key)

        if public_key == target_pubkey:
            logging.info(f"Found private key directly: {hex(private_key)}")
            save_found_key(private_key, lock)
            result_queue.put(private_key)
            return private_key

        # Store Tame Points Efficiently
        tame_points[public_key] = private_key
        tame_points_queue.put(public_key)
        save_progress(private_key, lock)  # Save progress periodically

        # 🏇 Log the jump
        logging.info(f"Tame Kangaroo Jumped to: {hex(private_key)} (-{step_size})")

        # Adjust Jumping Logic with heuristic pruning
        step_size = adaptive_step_size(private_key)
        private_key -= step_size
        if private_key < START_KEY:
            private_key = START_KEY  # Prevent jumping out of range

        # Log progress periodically
        if private_key % 1000 == 0:  # Adjust the modulus value for more or less frequent logging
            logging.info(f"Tame Kangaroo at: {hex(private_key)}")

    logging.info(f"Tame Kangaroo Finished! {len(tame_points)} points recorded.")

# 🦘 Wild Kangaroo (Forward Search for Collision)
def wild_kangaroo_search(proc_id, result_queue, tame_points, tame_points_queue, last_known_position, lock):
    """Wild kangaroo jumps forward randomly, checking against tame points with heuristic pruning."""
    wild_position = last_known_position or load_progress() or random.randint(START_KEY, (START_KEY + END_KEY) // 2)
    logging.info(f"Wild Kangaroo-{proc_id} started at {hex(wild_position)}")

    while wild_position < END_KEY:
        public_key = private_to_public(wild_position)

        # Check against shared tame points
        if public_key in tame_points:
            tame_private_key = tame_points[public_key]
            private_key = tame_private_key + wild_position
            logging.info(f"MATCH FOUND by Process-{proc_id}: {hex(private_key)}")
            result_queue.put(private_key)
            return

        # 🆕 Fetch additional tame points frequently
        while True:
            try:
                tame_key = tame_points_queue.get_nowait()
                tame_points[tame_key] = tame_key  # Ensure updates
            except Empty:
                break
        save_progress(wild_position, lock)  # Save progress periodically

        # 🏇 Adaptive step size selection with heuristic pruning
        step_size = adaptive_step_size(wild_position)
        wild_position += step_size

        # 🔄 Ensure the wild kangaroo is moving forward
        if wild_position >= END_KEY:
            wild_position = random.randint(START_KEY, (START_KEY + END_KEY) // 2)  # Restart within range

        # Log the Wild Kangaroo jumps (ensures logging every jump)
        logging.info(f"Wild-{proc_id} jumped to: {hex(wild_position)} | Step Size: {step_size}")

    # Return last known position if search ends
    return wild_position

def adaptive_step_size(current_position):
    """Dynamically adjust the step size based on the current position with heuristic pruning."""
    distance_to_target = END_KEY - current_position
    if distance_to_target > 2**20:
        return random.randint(2**18, 2**20)  # Larger jumps for distant positions
    elif distance_to_target > 2**16:
        return random.randint(2**16, 2**18)  # Medium jumps for closer positions
    else:
        return random.randint(2**14, 2**16)  # Smaller jumps for near-target positions

# 🏁 Multiprocessing Execution
def start_search():
    """Launch multiple processes for BSGS and Kangaroo searches concurrently."""
    print_end_key()  # Print END_KEY before starting the search
    logging.info("Starting Hybrid BSGS and Kangaroo Search...")

    # Convert target public key to elliptic curve point
    target_pubkey_point = hex_to_pubkey(TARGET_PUBLIC_KEY)
    if not target_pubkey_point:
        logging.error("Invalid target public key format!")
        return

    with Manager() as manager:
        tame_points = manager.dict()
        tame_points_queue = manager.Queue()
        result_queue = manager.Queue()
        lock = Lock()

        # Start BSGS Search in a separate process
        bsgs_proc = Process(target=bsgs, args=(target_pubkey_point, START_KEY, END_KEY, result_queue))
        bsgs_proc.start()

        # Start Tame Kangaroo
        tame_proc = Process(target=tame_kangaroo_search, args=(tame_points, tame_points_queue, END_KEY, lock, result_queue))
        tame_proc.start()

        # Start Wild Kangaroo processes
        processes = []
        last_known_position = load_progress()  # Load last known position
        logging.info(f"Starting Wild Kangaroo Search with {PROCESS_COUNT} processes...")

        for i in range(PROCESS_COUNT):
            p = Process(target=wild_kangaroo_search, args=(i, result_queue, tame_points, tame_points_queue, last_known_position, lock))
            p.start()
            processes.append(p)

        def signal_handler(sig, frame):
            logging.warning("Search interrupted by user. Cleaning up processes...")
            for p in processes:
                if p.is_alive():
                    p.terminate()
            if bsgs_proc.is_alive():
                bsgs_proc.terminate()
            if tame_proc.is_alive():
                tame_proc.terminate()
            exit(0)

        # Register signal handler for graceful termination
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Monitor results and terminate on success
        try:
            while any(p.is_alive() for p in processes) or bsgs_proc.is_alive() or tame_proc.is_alive():
                if not result_queue.empty():
                    found_key = result_queue.get()
                    logging.info(f"Validating found key: {found_key}")
                    derived_public_key = private_to_compressed_public_key(hex(found_key)[2:])
                    logging.info(f"Derived Public Key: {derived_public_key}")
                    if derived_public_key == TARGET_PUBLIC_KEY:
                        save_found_key(found_key, lock)
                        logging.info(f"Private Key Found: {hex(found_key)}")

                        # Terminate all processes
                        for p in processes:
                            if p.is_alive():
                                p.terminate()
                        if bsgs_proc.is_alive():
                            bsgs_proc.terminate()
                        if tame_proc.is_alive():
                            tame_proc.terminate()
                        return
                    else:
                        logging.info(f"Found private key does NOT correspond to the target public key.\nDerived Public Key: {derived_public_key}")

            # Wait for completion
            bsgs_proc.join()
            tame_proc.join()
            for p in processes:
                p.join()

            logging.info("Search complete. No match found.")

        except KeyboardInterrupt:
            logging.warning("Search interrupted by user. Cleaning up processes...")
            for p in processes:
                if p.is_alive():
                    p.terminate()
            if bsgs_proc.is_alive():
                bsgs_proc.terminate()
            if tame_proc.is_alive():
                tame_proc.terminate()

# 📌 Save found keys
def save_found_key(private_key, lock):
    """Save a found private key to a file."""
    with lock:
        try:
            with open(FOUND_KEYS_FILE, "a") as f:
                f.write(f"{hex(private_key)}\n")
            logging.info(f"FOUND MATCH! Private Key: {hex(private_key)} (Saved to {FOUND_KEYS_FILE})")
        except Exception as e:
            logging.error(f"Error saving found key: {e}")

# 🚀 Start the optimized search
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hybrid BSGS and Kangaroo Search")
    parser.add_argument("--target", type=str, default=TARGET_PUBLIC_KEY, help="Target public key to search for")
    parser.add_argument("--start", type=int, default=START_KEY, help="Starting key for the search")
    parser.add_argument("--end", type=int, default=END_KEY, help="Ending key for the search")
    parser.add_argument("--processes", type=int, default=PROCESS_COUNT, help="Number of wild kangaroo processes")
    args = parser.parse_args()

    TARGET_PUBLIC_KEY = args.target
    START_KEY = args.start
    END_KEY = args.end
    PROCESS_COUNT = args.processes

    start_search()