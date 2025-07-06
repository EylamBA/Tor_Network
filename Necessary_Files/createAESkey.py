import time

# Manual random number generator using time (basic implementation)
def manual_random_byte():
    t = time.time()  # Get the current time as a float
    t_int = int((t - int(t)) * 1000000)  # Use microseconds part
    return t_int & 0xFF  # Return the last 8 bits as a random byte

# Generate a string with random bytes of desired length
def generate_random_input(length=16):
    random_data = ""
    for _ in range(length):
        random_byte = manual_random_byte()
        random_data += chr(random_byte)  # Convert byte to character
        time.sleep(0.001)  # Slight delay to change time-based randomness
    return random_data

# Manual hashing function (simplified SHA-1 inspired)
def simple_hash(data):
    h0, h1, h2, h3 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    data_bytes = [ord(c) for c in data]
    original_length = len(data_bytes) * 8
    data_bytes.append(0x80)
    while (len(data_bytes) * 8 + 64) % 512 != 0:
        data_bytes.append(0x00)
    length_bytes = [(original_length >> (8 * i)) & 0xFF for i in range(7, -1, -1)]
    data_bytes.extend(length_bytes)
    
    for chunk_index in range(0, len(data_bytes), 64):
        chunk = data_bytes[chunk_index:chunk_index + 64]
        w = []
        for i in range(0, 64, 4):
            word = (chunk[i] << 24) | (chunk[i + 1] << 16) | (chunk[i + 2] << 8) | chunk[i + 3]
            w.append(word)
        for i in range(16, 80):
            val = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            w.append((val << 1 | val >> 31) & 0xFFFFFFFF)
        a, b, c, d = h0, h1, h2, h3
        for i in range(80):
            f = (b & c) | (~b & d)
            temp = (a + f + w[i]) & 0xFFFFFFFF
            a, b, c, d = temp, a, (b << 30 | b >> 2) & 0xFFFFFFFF, c
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
    
    hash_result = (
        (h0 >> 24) & 0xFF, (h0 >> 16) & 0xFF, (h0 >> 8) & 0xFF, h0 & 0xFF,
        (h1 >> 24) & 0xFF, (h1 >> 16) & 0xFF, (h1 >> 8) & 0xFF, h1 & 0xFF,
        (h2 >> 24) & 0xFF, (h2 >> 16) & 0xFF, (h2 >> 8) & 0xFF, h2 & 0xFF,
        (h3 >> 24) & 0xFF, (h3 >> 16) & 0xFF, (h3 >> 8) & 0xFF, h3 & 0xFF
    )
    
    return bytes(hash_result)

# Function to generate AES key (16 bytes) from random input
def generate_aes_key_from_random():
    random_input = generate_random_input(32)  # Generate 32 random characters
    hashed_value = simple_hash(random_input)
    return hashed_value[:16]  # Truncate to 16 bytes
