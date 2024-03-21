import asyncio
import base64
import json
import os

import pendulum
import websockets
from argon2 import PasswordHasher
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Ulterior:

    def __init__(self):
        self.current_id = 0
        self.private_key = None
        self.secret_key = None
        self.websocket = None

        self.uid = self.generate_id()

    async def connect(self):
        self.websocket = await websockets.connect("ws://localhost:4448")

    async def send_key(self):
        x448_public, x448_private = self.generate_x448_key_pair()
        self.private_key = x448_private
        message_data = {
            'type': 'key',
            'data': base64.b64encode(x448_public.public_bytes_raw()).decode(),
            'salt': base64.b64encode(bytes(str(self.uid), "utf-8")).decode(),
        }
        encoded_key = base64.b64encode(json.dumps(message_data).encode()).decode()
        await self.websocket.send(encoded_key)

    async def send_message(self, message):
        encrypted_message = self.encrypt_message(message, self.secret_key)
        message_data = {
            'type': 'message',
            'data': base64.b64encode(encrypted_message).decode()
        }
        encoded_message = base64.b64encode(json.dumps(message_data).encode()).decode()
        await self.websocket.send(encoded_message)

    async def exchange_keys(self):
        await self.send_key()
        while self.secret_key is None:
            await asyncio.sleep(1)

    async def active_task(self):
        while True:
            received_message = await self.websocket.recv()
            decoded_message = base64.b64decode(received_message).decode()
            message_data = json.loads(decoded_message)

            if message_data['type'] == 'key':
                data = message_data['data']
                decoded_key = base64.b64decode(data)
                peer_public_key = X448PublicKey.from_public_bytes(decoded_key)
                shared_key = self.private_key.exchange(peer_public_key)
                salt = base64.b64decode(message_data['salt'])
                derived_key = self.derive_key(shared_key, salt, 32)
                self.secret_key = derived_key
            elif message_data['type'] == 'message':
                decoded_data = base64.b64decode(message_data['data'])
                decrypted_message = self.decrypt_message(decoded_data, self.secret_key)
                print(f"\nreceived: {decrypted_message}")

    def generate_id(self):
        timestamp = pendulum.now().int_timestamp
        return (timestamp << 8) | (self.current_id & 0xFF)

    @staticmethod
    def encrypt_message(message: bytes, private_key: bytes) -> bytes:
        chacha = ChaCha20Poly1305(private_key)
        chacha_nonce = os.urandom(12)
        chacha_ciphertext = chacha.encrypt(chacha_nonce, message, None)

        aesgcm = AESGCM(private_key)
        aesgcm_nonce = os.urandom(12)
        final_ciphertext = aesgcm.encrypt(aesgcm_nonce, chacha_ciphertext, None)
        ciphertext_with_nonces = chacha_nonce + aesgcm_nonce + final_ciphertext

        return ciphertext_with_nonces

    @staticmethod
    def decrypt_message(ciphertext_with_nonces: bytes, private_key: bytes) -> str:
        try:
            chacha_nonce = ciphertext_with_nonces[:12]
            aesgcm_nonce = ciphertext_with_nonces[12:24]
            final_ciphertext = ciphertext_with_nonces[24:]

            aesgcm = AESGCM(private_key)
            chacha_ciphertext = aesgcm.decrypt(aesgcm_nonce, final_ciphertext, None)

            chacha = ChaCha20Poly1305(private_key)
            plaintext = chacha.decrypt(chacha_nonce, chacha_ciphertext, None)

            return str(plaintext.decode())
        except InvalidTag as e:
            return f"Could not decrypt the message: {str(e)}"

    @staticmethod
    def derive_key(password: bytes, id_salt: bytes, key_size: int):
        argon2 = PasswordHasher()
        password_hash = argon2.hash(password, salt=id_salt)
        hash_bytes = bytes(password_hash, "utf-8")

        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=key_size,
            salt=id_salt,
            info=None,
        )

        return hkdf.derive(hash_bytes)

    @staticmethod
    def generate_x448_key_pair():
        private_key = X448PrivateKey.generate()
        public_key = private_key.public_key()
        return public_key, private_key


async def user_input(ulterior):
    print("Enter a message to send (or 'exit' to quit): ")

    while True:
        message = await asyncio.to_thread(input)

        if message.lower() == 'exit':
            break

        msg_bytes = bytes(message, "utf-8")
        await ulterior.send_message(msg_bytes)

    await ulterior.websocket.close()


async def main():
    ulterior = Ulterior()
    await ulterior.connect()
    asyncio.create_task(ulterior.active_task())
    await ulterior.exchange_keys()
    await user_input(ulterior)


if __name__ == "__main__":
    asyncio.run(main())
