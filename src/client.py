import asyncio
import base64
import logging
import os
import sys
from collections import OrderedDict
from typing import Optional, Tuple, Callable, Any, Dict

import msgpack
import pendulum
import websockets
from qasync import QEventLoop, asyncSlot

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from PyQt6 import QtWidgets, QtGui

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
ULTERIOR_DIR = os.path.join(os.path.expanduser("~"), ".ulterior")
os.makedirs(ULTERIOR_DIR, exist_ok=True)


def key_path(filename: str) -> str:
    return os.path.join(ULTERIOR_DIR, filename)


def canonical_pack(data: Any) -> bytes:
    if isinstance(data, dict):
        sorted_data = OrderedDict(
            sorted(
                (
                    (k, canonical_pack(v) if isinstance(v, dict) else v)
                    for k, v in data.items()
                ),
                key=lambda item: item[0],
            )
        )
        return msgpack.packb(sorted_data, use_bin_type=True)
    elif isinstance(data, list):
        return msgpack.packb(
            [canonical_pack(item) if isinstance(item, dict) else item for item in data],
            use_bin_type=True,
        )
    else:
        return msgpack.packb(data, use_bin_type=True)


def sign_data(private_key: Ed448PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def verify_data(public_key: Ed448PublicKey, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def derive_key(shared_key: bytes, salt: bytes, key_size: int) -> Optional[bytes]:
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=key_size,
            salt=salt,
            info=b"ulterior handshake",
        )
        return hkdf.derive(shared_key)
    except Exception as e:
        logging.error("Key derivation error: %s", e)
        return None


def encrypt_message(message: bytes, key: bytes) -> Optional[bytes]:
    try:
        chacha = ChaCha20Poly1305(key)
        chacha_nonce = os.urandom(12)
        chacha_ciphertext = chacha.encrypt(chacha_nonce, message, None)
        aesgcm = AESGCMSIV(key)
        aesgcm_nonce = os.urandom(12)
        final_ciphertext = aesgcm.encrypt(aesgcm_nonce, chacha_ciphertext, None)
        return chacha_nonce + aesgcm_nonce + final_ciphertext
    except Exception as e:
        logging.error("Encryption error: %s", e)
        return None


def decrypt_message(ciphertext_with_nonces: bytes, key: bytes) -> str:
    try:
        chacha_nonce = ciphertext_with_nonces[:12]
        aesgcm_nonce = ciphertext_with_nonces[12:24]
        final_ciphertext = ciphertext_with_nonces[24:]
        aesgcm = AESGCMSIV(key)
        chacha_ciphertext = aesgcm.decrypt(aesgcm_nonce, final_ciphertext, None)
        chacha = ChaCha20Poly1305(key)
        plaintext = chacha.decrypt(chacha_nonce, chacha_ciphertext, None)
        return plaintext.decode("utf-8")
    except InvalidTag as e:
        return f"Decryption failed: {e}"
    except Exception as e:
        return f"Unexpected decryption error: {e}"


def generate_x448_key_pair() -> Tuple[X448PublicKey, X448PrivateKey]:
    private_key = X448PrivateKey.generate()
    public_key = private_key.public_key()
    return public_key, private_key


def load_or_generate_trusted_server_public_key(
    filename: Optional[str] = None,
) -> Ed448PublicKey:
    if filename is None:
        filename = key_path("server_public.pem")
    if os.path.exists(filename):
        try:
            with open(filename, "rb") as f:
                pem_data = f.read()
            public_key = serialization.load_pem_public_key(pem_data)
            logging.info("Loaded trusted server public key from '%s'.", filename)
            return public_key
        except Exception as e:
            logging.error("Error loading trusted server public key: %s", e)
            raise
    else:
        logging.info(
            "Trusted server public key '%s' not found. Generating a new one for testing.",
            filename,
        )
        temp_private_key = Ed448PrivateKey.generate()
        temp_public_key = temp_private_key.public_key()
        pem_public = temp_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        try:
            with open(filename, "wb") as f:
                f.write(pem_public)
            logging.info(
                "Generated and saved new trusted server public key to '%s'.", filename
            )
        except Exception as e:
            logging.error("Error saving trusted server public key: %s", e)
            raise
        return temp_public_key


def load_or_generate_client_static_keys(
    private_filename: Optional[str] = None, public_filename: Optional[str] = None
) -> Tuple[Ed448PrivateKey, Ed448PublicKey]:
    if private_filename is None:
        private_filename = key_path("client_private.pem")
    if public_filename is None:
        public_filename = key_path("client_public.pem")
    if os.path.exists(private_filename) and os.path.exists(public_filename):
        try:
            with open(private_filename, "rb") as f:
                private_pem = f.read()
            private_key = serialization.load_pem_private_key(private_pem, password=None)
            with open(public_filename, "rb") as f:
                public_pem = f.read()
            public_key = serialization.load_pem_public_key(public_pem)
            logging.info(
                "Loaded client static keys from '%s' and '%s'.",
                private_filename,
                public_filename,
            )
            return private_key, public_key
        except Exception as e:
            logging.error("Error loading client keys: %s", e)
            raise
    else:
        private_key = Ed448PrivateKey.generate()
        public_key = private_key.public_key()
        try:
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(private_filename, "wb") as f:
                f.write(private_pem)
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with open(public_filename, "wb") as f:
                f.write(public_pem)
            logging.info(
                "Generated new client static keys and saved to '%s' and '%s'.",
                private_filename,
                public_filename,
            )
        except Exception as e:
            logging.error("Error saving client keys: %s", e)
            raise
        return private_key, public_key


class Ulterior:
    def __init__(self, address: str) -> None:
        self.address: str = address
        self.current_id: int = 0
        self.uid: int = self.generate_id()
        self.ephemeral_private_key: Optional[X448PrivateKey] = None
        self.secret_key: Optional[bytes] = None
        self.websocket: Optional[websockets.WebSocketClientProtocol] = None
        self.static_private_key, self.static_public_key = (
            load_or_generate_client_static_keys()
        )
        pem_public = self.static_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        logging.info("Client static public key (PEM):\n%s", pem_public.decode())
        self.trusted_server_public_key: Ed448PublicKey = (
            load_or_generate_trusted_server_public_key()
        )
        self.on_message: Optional[Callable[[str], None]] = None
        self._active_task: Optional[asyncio.Task] = None
        self._key_exchange_task: Optional[asyncio.Task] = None

    async def connect(self) -> None:
        while True:
            try:
                self.websocket = await websockets.connect(self.address)
                logging.info(
                    "Connected to server at %s.", self.websocket.remote_address
                )
                break
            except Exception as e:
                logging.error(
                    "Failed to connect to the server: %s. Retrying in 3 seconds.", e
                )
                await asyncio.sleep(3)

    async def send_key(self) -> None:
        try:
            x448_public, x448_private = generate_x448_key_pair()
            self.ephemeral_private_key = x448_private
            x448_public_bytes = x448_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            payload: Dict[str, Any] = {
                "type": "key",
                "data": base64.b85encode(x448_public_bytes).decode("utf-8"),
                "salt": base64.b85encode(str(self.uid).encode("utf-8")).decode("utf-8"),
            }
            payload_bytes = canonical_pack(payload)
            signature = sign_data(self.static_private_key, payload_bytes)
            payload["signature"] = base64.b85encode(signature).decode("utf-8")
            packed_data = canonical_pack(payload)
            await self.websocket.send(packed_data)
            logging.info("Sent ephemeral key to the server.")
        except Exception as e:
            logging.error("Error sending key: %s", e)

    async def send_message(self, message: bytes) -> None:
        try:
            if not self.secret_key:
                raise ValueError("Secret key is not set")
            encrypted_message = encrypt_message(message, self.secret_key)
            if encrypted_message is None:
                return
            payload: Dict[str, Any] = {
                "type": "message",
                "data": base64.b85encode(encrypted_message).decode("utf-8"),
            }
            payload_bytes = canonical_pack(payload)
            signature = sign_data(self.static_private_key, payload_bytes)
            payload["signature"] = base64.b85encode(signature).decode("utf-8")
            packed_message = canonical_pack(payload)
            await self.websocket.send(packed_message)
            logging.info("Sent encrypted message to the server.")
        except Exception as e:
            logging.error("Error sending message: %s", e)

    async def exchange_keys(self) -> None:
        await self.send_key()
        while self.secret_key is None:
            await asyncio.sleep(1)

    async def active_task(self) -> None:
        try:
            while True:
                received_message = await self.websocket.recv()
                unpacked_data = msgpack.unpackb(received_message, raw=False)
                if not self._verify_and_process(unpacked_data):
                    continue
        except websockets.ConnectionClosed:
            logging.info("Websocket connection closed.")
        except Exception as e:
            logging.error("Error in active task: %s", e)

    def _verify_and_process(self, message: Dict[str, Any]) -> bool:
        signature_b64 = message.get("signature")
        if not signature_b64:
            logging.warning("No signature found in message; discarding.")
            return False
        signature = base64.b85decode(signature_b64)
        payload = {k: v for k, v in message.items() if k != "signature"}
        payload_bytes = canonical_pack(payload)
        if not verify_data(self.trusted_server_public_key, signature, payload_bytes):
            logging.warning("Signature verification failed; discarding message.")
            return False
        msg_type = message.get("type")
        if msg_type == "key":
            return self._process_key_message(message)
        elif msg_type == "message":
            return self._process_text_message(message)
        else:
            logging.warning("Unknown message type: %s", msg_type)
            return False

    def _process_key_message(self, message: Dict[str, Any]) -> bool:
        try:
            data = message["data"]
            decoded_key = base64.b85decode(data)
            peer_public_key = X448PublicKey.from_public_bytes(decoded_key)
            shared_key = self.ephemeral_private_key.exchange(peer_public_key)
            salt = base64.b85decode(message["salt"])
            derived = derive_key(shared_key, salt, 32)
            if derived is None:
                return False
            self.secret_key = derived
            logging.info("Derived shared secret key.")
            return True
        except Exception as e:
            logging.error("Error processing key message: %s", e)
            return False

    def _process_text_message(self, message: Dict[str, Any]) -> bool:
        try:
            decoded_data = base64.b85decode(message["data"])
            decrypted_message = decrypt_message(decoded_data, self.secret_key)
            logging.info("Received message: %s", decrypted_message)
            if self.on_message:
                self.on_message(decrypted_message)
            return True
        except Exception as e:
            logging.error("Error processing text message: %s", e)
            return False

    def generate_id(self) -> int:
        timestamp = pendulum.now().int_timestamp
        return (timestamp << 8) | (self.current_id & 0xFF)

    async def close(self) -> None:
        """Gracefully close the websocket and cancel active tasks."""
        logging.info("Shutting down Ulterior client...")
        try:
            if self.websocket:
                await self.websocket.close()
                logging.info("Websocket closed gracefully.")
        except Exception as e:
            logging.error("Error closing websocket: %s", e)

        if self._active_task:
            self._active_task.cancel()
        if self._key_exchange_task:
            self._key_exchange_task.cancel()


class ClientGUI(QtWidgets.QMainWindow):
    def __init__(self, ulterior: Ulterior, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ulterior = ulterior
        self.setWindowTitle("Ulterior Client")
        self.resize(600, 400)
        self._init_ui()

    def _init_ui(self) -> None:
        central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)
        self.message_display = QtWidgets.QTextEdit(self)
        self.message_display.setReadOnly(True)
        self.message_display.setStyleSheet("font-size: 14px;")
        layout.addWidget(self.message_display)
        input_layout = QtWidgets.QHBoxLayout()
        self.message_input = QtWidgets.QLineEdit(self)
        self.message_input.setPlaceholderText("Type your message here...")
        self.message_input.setStyleSheet("font-size: 14px; padding: 4px;")
        input_layout.addWidget(self.message_input)
        self.send_button = QtWidgets.QPushButton("Send", self)
        self.send_button.setStyleSheet(
            "QPushButton { background-color: #5cb85c; color: white; font-size: 14px; padding: 6px 12px; border: none; border-radius: 4px; } "
            "QPushButton:hover { background-color: #4cae4c; }"
        )
        input_layout.addWidget(self.send_button)
        layout.addLayout(input_layout)
        self.status_bar = QtWidgets.QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Connecting to server...")
        self.send_button.clicked.connect(self.on_send_clicked)
        self.message_input.returnPressed.connect(self.on_send_clicked)

    @asyncSlot()
    async def on_send_clicked(self) -> None:
        text = self.message_input.text().strip()
        if not text:
            return
        self.append_message("Me", text)
        try:
            await self.ulterior.send_message(text.encode("utf-8"))
        except Exception as e:
            self.append_message("Error", f"Failed to send message: {e}")
        self.message_input.clear()

    def append_message(self, sender: str, message: str) -> None:
        self.message_display.append(f"<b>{sender}:</b> {message}")

    def update_status(self, message: str) -> None:
        self.status_bar.showMessage(message)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        logging.info("Closing GUI, initiating graceful shutdown...")
        asyncio.create_task(self.ulterior.close())
        event.accept()


async def run_client_gui() -> None:
    ulterior = Ulterior("ws://192.168.50.254:4448")
    await ulterior.connect()
    gui = ClientGUI(ulterior)
    gui.show()
    gui.update_status("Connected. Exchanging keys...")
    ulterior.on_message = lambda msg: gui.append_message("Server", msg)
    ulterior._key_exchange_task = asyncio.create_task(ulterior.exchange_keys())
    ulterior._active_task = asyncio.create_task(ulterior.active_task())
    while ulterior.secret_key is None:
        await asyncio.sleep(0.1)
    gui.update_status("Secure connection established. Ready to chat.")


def main() -> None:
    app = QtWidgets.QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    with loop:
        loop.create_task(run_client_gui())
        loop.run_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Program interrupted by user.")
