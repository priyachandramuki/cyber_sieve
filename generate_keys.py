from Crypto.PublicKey import RSA
import os

# Create a folder for keys if not exists
os.makedirs("keys", exist_ok=True)

# Generate a 2048-bit RSA key pair
key = RSA.generate(2048)

private_key = key.export_key()
public_key = key.publickey().export_key()

# Save the private key
with open("keys/private.pem", "wb") as prv_file:
    prv_file.write(private_key)

# Save the public key
with open("keys/public.pem", "wb") as pub_file:
    pub_file.write(public_key)

print("✅ RSA key pair generated and saved in 'keys/' folder.")
