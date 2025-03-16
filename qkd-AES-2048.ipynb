# QKD + AES-2048
# Install necessary packages
!pip install qiskit qiskit-aer pycryptodome

# Importing required libraries
import random
import hashlib
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
import ipywidgets as widgets
from IPython.display import display, clear_output
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import json

class QKDSimulator:
    def __init__(self):
        self.qubit_length = 1024
        self.simulator = AerSimulator(method='automatic')
        self.setup_gui()

    def setup_gui(self):
        """
        Sets up the Jupyter widgets for encryption and decryption.
        """
        # ===================
        # ENCRYPTION WIDGETS
        # ===================
        self.message_entry = widgets.Text(
            value='',
            placeholder='Enter your message here',
            description='Message:',
            style={'description_width': 'initial'},
            layout=widgets.Layout(width='70%')
        )
        self.encrypt_password_entry = widgets.Password(
            value='',
            placeholder='Enter AES-2048 password for encryption',
            description='Encrypt PW:',
            style={'description_width': 'initial'},
            layout=widgets.Layout(width='70%')
        )
        self.encrypt_button = widgets.Button(
            description="Encrypt Message",
            button_style='success'
        )
        self.encrypt_button.on_click(self.encrypt_message)

        self.encrypted_label = widgets.HTML(value="<b>Encrypted Message:</b> ")
        self.decrypted_label = widgets.HTML(value="<b>Decrypted Message:</b> ")
        self.qkd_key_label = widgets.HTML(value="<b>QKD Key Used:</b> ")

        # ===================
        # DECRYPTION WIDGETS
        # ===================
        self.external_encrypted_entry = widgets.Text(
            value='',
            placeholder='Paste your encrypted message here',
            description='Encrypted Input:',
            style={'description_width': 'initial'},
            layout=widgets.Layout(width='70%')
        )
        self.decrypt_qkd_key_entry = widgets.Text(
            value='',
            placeholder='Enter the QKD key provided with the message',
            description='Decrypt QKD:',
            style={'description_width': 'initial'},
            layout=widgets.Layout(width='70%')
        )
        self.decrypt_password_entry = widgets.Password(
            value='',
            placeholder='Enter AES-2048 password for decryption',
            description='Decrypt PW:',
            style={'description_width': 'initial'},
            layout=widgets.Layout(width='70%')
        )
        self.decrypt_button = widgets.Button(
            description="Decrypt Message",
            button_style='success'
        )
        self.decrypt_button.on_click(self.decrypt_external_message)

        self.external_decrypted_label = widgets.HTML(value="<b>External Decrypted Message:</b> ")

        # Display all widgets
        display(
            # Encryption area
            self.message_entry,
            self.encrypt_password_entry,
            self.encrypt_button,
            self.encrypted_label,
            self.decrypted_label,
            self.qkd_key_label,

            # Decryption area
            self.external_encrypted_entry,
            self.decrypt_qkd_key_entry,
            self.decrypt_password_entry,
            self.decrypt_button,
            self.external_decrypted_label
        )

    # =====================================================
    #                   ENCRYPTION
    # =====================================================
    def encrypt_message(self, _):
        """
        Encrypts the text from self.message_entry with a two-layer encryption:
        1. AES-2048
        2. A simplified "QKD" bitwise encryption (for demonstration).
        The QKD key used (after privacy amplification) is displayed for sharing.
        """
        plaintext = self.message_entry.value
        password = self.encrypt_password_entry.value.strip()
        if not password:
            password = "secure-password"  # Fallback if left empty

        # 1) AES-2048 encryption
        ivs, ciphertext, salt = self.aes_2048_encrypt(plaintext.encode(), password)
        encryption_output = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "ivs": [base64.b64encode(iv).decode() for iv in ivs],
            "salt": base64.b64encode(salt).decode(),
        }
        # Base64 the JSON
        obfuscated_output = base64.b64encode(json.dumps(encryption_output).encode()).decode()

        # 2) QKD-based encryption (bitwise)
        key = self.generate_random_key()
        circuit = self.prepare_qubits(key)
        alice_bases = [random.choice(['X', 'Z']) for _ in range(self.qubit_length)]
        bob_bases = [random.choice(['X', 'Z']) for _ in range(self.qubit_length)]
        alice_key = self.measure_qubits(circuit)
        sifted_indices = self.compare_bases(alice_bases, bob_bases)
        sifted_key = self.sift_key(alice_key, sifted_indices)
        error_corrected_key = self.error_correction(sifted_key)
        # QKD key (after privacy amplification)
        privacy_amplified_key = self.privacy_amplification(error_corrected_key)

        # Convert the base64 to bits, then encrypt
        message_bits = self.classical_communication(obfuscated_output)
        encrypted_message = self.encrypt_message_bits(message_bits, privacy_amplified_key)
        encrypted_bytes = bytearray(int(''.join(map(str, encrypted_message[i:i+8])), 2) for i in range(0, len(encrypted_message), 8))
        encrypted_message_base64 = base64.b64encode(encrypted_bytes).decode()


        # Optional self-test: Immediately decrypt to verify
        try:
            decrypted_bits = self.decrypt_message(encrypted_message, privacy_amplified_key)
            decrypted_obfuscated = self.binary_to_ascii(decrypted_bits)
            decoded_json = json.loads(base64.b64decode(decrypted_obfuscated).decode())
            ciph = base64.b64decode(decoded_json["ciphertext"])
            ivs_dec = [base64.b64decode(iv) for iv in decoded_json["ivs"]]
            salt_dec = base64.b64decode(decoded_json["salt"])
            decrypted_plaintext = self.aes_2048_decrypt(ciph, password, ivs_dec, salt_dec)
            self.decrypted_label.value = f"<b>Decrypted Message:</b> {decrypted_plaintext.decode()}"
        except Exception as e:
            # If for some reason our own immediate check fails
            self.decrypted_label.value = f"<b>Decrypted Message:</b> (Self-test failed: {str(e)})"

        # Display final encryption results
        self.encrypted_label.value = (
            "<b>Encrypted Message (Copy/Paste - Base64):</b><br>"
            f"<textarea rows='3' style='width: 100%;'>{encrypted_message_base64}</textarea>"
        )

        qkd_key_str = ''.join(map(str, privacy_amplified_key))
        self.qkd_key_label.value = f"<b>QKD Key Used:</b> {qkd_key_str}"

    # =====================================================
    #                   DECRYPTION
    # =====================================================
    def decrypt_external_message(self, _):
        """
        Decrypts an externally provided encrypted message using:
        1. The user-provided AES-2048 password (self.decrypt_password_entry)
        2. The externally provided QKD key (self.decrypt_qkd_key_entry).
        """
        # 1) Retrieve user inputs
        encrypted_input = self.external_encrypted_entry.value.strip()
        qkd_key_str = self.decrypt_qkd_key_entry.value.strip()
        password = self.decrypt_password_entry.value.strip()
        if not encrypted_input:
            self.external_decrypted_label.value = (
                "<b>External Decrypted Message:</b> Error: No encrypted input provided."
            )
            return
        if not qkd_key_str:
            self.external_decrypted_label.value = (
                "<b>External Decrypted Message:</b> Error: No QKD key provided."
            )
            return
        if not password:
            self.external_decrypted_label.value = (
                "<b>External Decrypted Message:</b> Error: No AES password provided."
            )
            return

        # 2) Convert the ASCII-encoded ciphertext to bits
        try:
            encrypted_bytes = base64.b64decode(encrypted_input)
        except Exception as e:
            self.external_decrypted_label.value = (
                f"<b>External Decrypted Message:</b> Error decoding Base64 input: {str(e)}"
            )
            return
        encrypted_bits = [int(bit) for byte in encrypted_bytes for bit in bin(byte)[2:].zfill(8)]

        # 3) Convert the QKD key string to a list of bits
        try:
            qkd_key_bits = [int(bit_char) for bit_char in qkd_key_str]
        except ValueError:
            self.external_decrypted_label.value = (
                "<b>External Decrypted Message:</b> Error: QKD key must be a string of 0s/1s."
            )
            return

        # 4) Check length to avoid index errors
        if len(qkd_key_bits) == 0:
            self.external_decrypted_label.value = (
                "<b>External Decrypted Message:</b> Error: QKD key is empty."
            )
            return
        # We don't necessarily require them to match length exactly,
        # but we do check that the QKD key is not empty.
        # If the ciphertext is shorter, it's still fine, we just mod the key length.

        # 5) Decrypt with QKD key
        try:
            decrypted_message_bits = self.decrypt_message(encrypted_bits, qkd_key_bits)
            decrypted_obfuscated_output = self.binary_to_ascii(decrypted_message_bits)
        except IndexError as e:
            self.external_decrypted_label.value = (
                f"<b>External Decrypted Message:</b> Error: {str(e)}. "
                "Check QKD key length vs. ciphertext."
            )
            return

        # 6) Base64-decode and parse the AES JSON
        try:
            decoded_json = json.loads(base64.b64decode(decrypted_obfuscated_output).decode())
            ciphertext = base64.b64decode(decoded_json["ciphertext"])
            ivs = [base64.b64decode(iv) for iv in decoded_json["ivs"]]
            salt = base64.b64decode(decoded_json["salt"])
        except Exception as e:
            self.external_decrypted_label.value = (
                f"<b>External Decrypted Message:</b> Error reading AES data: {str(e)}"
            )
            return

        # 7) Perform AES-2048 decryption
        try:
            decrypted_plaintext = self.aes_2048_decrypt(ciphertext, password, ivs, salt)
            self.external_decrypted_label.value = (
                f"<b>External Decrypted Message:</b> {decrypted_plaintext.decode()}"
            )
        except Exception as e:
            self.external_decrypted_label.value = (
                f"<b>External Decrypted Message:</b> Error: {str(e)}"
            )

    # =====================================================
    #             AES-2048 (First-Layer)
    # =====================================================
    def aes_2048_encrypt(self, plaintext, password, salt=None, iterations=1600000):
        salt = salt or get_random_bytes(16)
        # Generate 8 subkeys of 256 bits each => 2048 bits total
        key_2048 = PBKDF2(password, salt, dkLen=256, count=iterations)
        keys = [key_2048[i * 32:(i + 1) * 32] for i in range(8)]

        # Prepend SHA-256 hash for integrity
        hash_obj = SHA256.new(plaintext)
        plaintext_hash = hash_obj.digest()
        plaintext_with_hash = plaintext_hash + plaintext

        ivs = [get_random_bytes(16) for _ in range(8)]
        ciphertext = plaintext_with_hash

        # Encrypt sequentially using each subkey
        for i in range(8):
            cipher = AES.new(keys[i], AES.MODE_CBC, ivs[i])
            padding = 16 - len(ciphertext) % 16
            ciphertext += bytes([padding]) * padding
            ciphertext = cipher.encrypt(ciphertext)

        return ivs, ciphertext, salt

    def aes_2048_decrypt(self, ciphertext, password, ivs, salt, iterations=1600000):
        key_2048 = PBKDF2(password, salt, dkLen=256, count=iterations)
        keys = [key_2048[i * 32:(i + 1) * 32] for i in range(8)]

        plaintext_with_hash = ciphertext
        # Decrypt in reverse order
        for i in reversed(range(8)):
            cipher = AES.new(keys[i], AES.MODE_CBC, ivs[i])
            plaintext_with_hash = cipher.decrypt(plaintext_with_hash)
            padding = plaintext_with_hash[-1]
            plaintext_with_hash = plaintext_with_hash[:-padding]

        # Verify integrity
        plaintext_hash = plaintext_with_hash[:32]
        plaintext = plaintext_with_hash[32:]
        hash_obj = SHA256.new(plaintext)
        if plaintext_hash != hash_obj.digest():
            raise ValueError("Integrity check failed.")
        return plaintext

    # =====================================================
    #             QKD-Like Logic (Second Layer)
    # =====================================================
    def measure_qubits(self, circuit):
        circuit.measure_all()
        result = self.simulator.run(circuit, shots=1).result()
        counts = result.get_counts()
        return list(counts.keys())[0]

    def generate_random_key(self):
        return [random.choice([0, 1]) for _ in range(self.qubit_length)]

    def prepare_qubits(self, key):
        circuit = QuantumCircuit(self.qubit_length, self.qubit_length)
        for i, bit in enumerate(key):
            if bit == 1:
                circuit.x(i)
        circuit.h(range(self.qubit_length))
        return circuit

    def compare_bases(self, alice_bases, bob_bases):
        return [i for i in range(len(alice_bases)) if alice_bases[i] == bob_bases[i]]

    def sift_key(self, key, indices):
        return [int(key[i]) for i in indices]

    def error_correction(self, sifted_key):
        # For demonstration, no real error correction is implemented
        return sifted_key

    def privacy_amplification(self, sifted_key):
        sifted_key_str = ''.join(map(str, sifted_key))
        hash_key = hashlib.sha256(sifted_key_str.encode()).digest()
        # Convert 256-bit hash to a list of bits
        return [int(bit) for byte in hash_key for bit in bin(byte)[2:].zfill(8)]

    def classical_communication(self, message):
        # Convert each character to its ASCII bit representation
        return [int(bit) for c in message for bit in bin(ord(c))[2:].zfill(8)]

    def encrypt_message_bits(self, message, key):
        # Bitwise addition mod 2 (like a simple XOR)
        return [(message[i] + key[i % len(key)]) % 2 for i in range(len(message))]

    def decrypt_message(self, ciphertext, key):
        # Bitwise subtraction mod 2 is the same as XOR
        return [(ciphertext[i] - key[i % len(key)]) % 2 for i in range(len(ciphertext))]

    def binary_to_ascii(self, message):
        chars = [
            chr(int(''.join(map(str, message[i:i+8])), 2))
            for i in range(0, len(message), 8)
        ]
        return ''.join(chars)

# Instantiate the simulator
qkd_simulator = QKDSimulator()
