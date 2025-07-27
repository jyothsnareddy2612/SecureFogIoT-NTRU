import time
from homomorphic import keygen, encrypt, decrypt

# Scheme's parameters
n = 2**4  # polynomial modulus degree
q = 2**15  # ciphertext modulus
t = 2**8  # plaintext modulus
poly_mod = [1] + [0] * (n - 1) + [1]  # polynomial modulus

# Key generation
start_time = time.time()
pk, sk = keygen(n, q, poly_mod)
keygen_time = time.time() - start_time

# Predefined input
plaintext = "ACK:n1:1234:4567:12.33"
ascii_values = [ord(char) for char in plaintext]  # Convert to ASCII list

# Encryption
start_time = time.time()
ciphertexts = [encrypt(pk, n, q, t, poly_mod, pt) for pt in ascii_values]
encryption_time = time.time() - start_time

# Decryption
start_time = time.time()
decrypted_values = [decrypt(sk, n, q, t, poly_mod, ct) for ct in ciphertexts]
decryption_time = time.time() - start_time

# Convert back to string
decrypted_text = ''.join(chr(val) for val in decrypted_values)

# Results
print("\n[+] Original Text: ", plaintext)
print("[+] ASCII Values: ", ascii_values)
print("[+] Ciphertexts: ", [(ct[0].tolist(), ct[1].tolist()) for ct in ciphertexts])
print("[+] Decrypted ASCII Values: ", decrypted_values)
print("[+] Decrypted Text: ", decrypted_text)

print("\n[+] Execution times:")
print("Key Generation: {:.6f} seconds".format(keygen_time))
print("Encryption: {:.6f} seconds".format(encryption_time))
print("Decryption: {:.6f} seconds".format(decryption_time))
print("Total Execution Time: {:.6f} seconds".format(keygen_time + encryption_time + decryption_time))
