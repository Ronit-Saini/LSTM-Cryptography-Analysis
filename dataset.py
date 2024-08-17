import csv
import random
import subprocess

# Function to call the C program and get the cipher text
def encrypt_present(key, plain_text):
    key = str(key)
    plain_text = str(plain_text)

    try:
        # Call the compiled C executable with the key and plain text as arguments
        result = subprocess.run(['./Present1.exe', key, plain_text], capture_output=True, text=True)
        
        if result.returncode == 0:
            output = result.stdout.strip()
            print(f"Encryption output: {output}")  # Debug statement
            
            # Extract the hexadecimal part of the ciphertext
            if "The ciphertext is:" in output:
                hex_cipher = output.split(":")[-1].strip()
            else:
                hex_cipher = output  # Assume output is already the hex value
            
            return hex_cipher
        else:
            print(f"Error in encryption: {result.stderr}")
            return None
    except Exception as e:
        print(f"Exception occurred: {e}")
        return None

# Function to convert a hexadecimal string to a 64-bit binary string
def hex_to_binary64(hex_text):
    integer_representation = int(hex_text, 16)
    binary_representation = bin(integer_representation)[2:].zfill(64)
    return list(binary_representation)

# Number of samples to generate
num_samples = 100000

# Generate a random 80-bit key in hexadecimal format (20 hex digits)
key = "00000000000000000000"

plain_texts=[]
# Open a CSV file to write the data
with open('dataset1.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)

    # Write the header for the first table (Plaintext bits)
    writer.writerow([f'Plaintext Bit {i}' for i in range(64)])

    # Write plaintext data directly
    for i in range(num_samples):
        # Generate a random 64-bit plain text in hexadecimal format
        plain_text = ''.join(random.choices('0123456789ABCDEF', k=16))
        plain_texts.append(plain_text)  # Store the plain text in the list
        
        # Convert the plaintext to 64-bit binary
        binary_plaintext = hex_to_binary64(plain_text)
        
        # Write plaintext binary data directly to the CSV
        writer.writerow(binary_plaintext)
        
        # Log progress every 10,000 iterations
        if (i + 1) % 10000 == 0:
            print(f"Processed {i + 1} plaintexts")
        
        # Flush the file buffer to ensure data is written immediately
        csvfile.flush()

    # Write an empty row to separate the tables
    writer.writerow([])

    # Write the header for the second table (Ciphertext bits)
    writer.writerow([f'Ciphertext Bit {i}' for i in range(64)])

    # Write ciphertext data directly
    for i, plain_text in enumerate(plain_texts):
        # Encrypt the stored plaintext using the PRESENT cipher
        cipher_text = encrypt_present(key, plain_text)
        
        if cipher_text is None:
            print(f"Skipping due to encryption failure for plaintext: {plain_text}")  # Debug statement
            continue  # Skip this iteration if encryption failed
        
        # Convert the ciphertext to 64-bit binary
        binary_ciphertext = hex_to_binary64(cipher_text)
        
        # Write ciphertext binary data directly to the CSV
        writer.writerow(binary_ciphertext)
        
        # Log progress every 10,000 iterations
        if (i + 1) % 10000 == 0:
            print(f"Processed {i + 1} ciphertexts")
        
        # Flush the file buffer to ensure data is written immediately
        csvfile.flush()

print("CSV file has been created and data written successfully.")

