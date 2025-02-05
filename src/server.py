import asyncio
import base64
import os
import logging
from collections import OrderedDict
from typing import Optional, Tuple

import msgpack
import websockets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Change to INFO or WARNING as needed
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("server")

ULTERIOR_DIR = os.path.join(os.path.expanduser("~"), ".ulterior")
if not os.path.exists(ULTERIOR_DIR):
    os.makedirs(ULTERIOR_DIR)
    logger.debug("Created directory: %s", ULTERIOR_DIR)


def key_path(filename: str) -> str:
    return os.path.join(ULTERIOR_DIR, filename)


def canonical_pack(data) -> bytes:
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


def load_or_generate_server_static_keys(
    private_filename: Optional[str] = None,
    public_filename: Optional[str] = None,
) -> Tuple[Ed448PrivateKey, Ed448PublicKey]:
    if private_filename is None:
        private_filename = key_path("server_private.pem")
    if public_filename is None:
        public_filename = key_path("server_public.pem")
    if os.path.exists(private_filename) and os.path.exists(public_filename):
        try:
            with open(private_filename, "rb") as f:
                private_pem = f.read()
            private_key = serialization.load_pem_private_key(private_pem, password=None)
            with open(public_filename, "rb") as f:
                public_pem = f.read()
            public_key = serialization.load_pem_public_key(public_pem)
            logger.info(
                "Loaded server static keys from '%s' and '%s'.",
                private_filename,
                public_filename,
            )
            return private_key, public_key
        except Exception as e:
            logger.error("Error loading server keys: %s", e)
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
            logger.info(
                "Generated new server static keys and saved to '%s' and '%s'.",
                private_filename,
                public_filename,
            )
        except Exception as e:
            logger.error("Error saving server keys: %s", e)
            raise
        return private_key, public_key


def load_or_generate_trusted_client_public_key(
    filename: Optional[str] = None,
) -> Ed448PublicKey:
    if filename is None:
        filename = key_path("client_public.pem")
    if os.path.exists(filename):
        try:
            with open(filename, "rb") as f:
                pem_data = f.read()
            public_key = serialization.load_pem_public_key(pem_data)
            logger.info("Loaded trusted client public key from '%s'.", filename)
            return public_key
        except Exception as e:
            logger.error("Error loading trusted client public key: %s", e)
            raise
    else:
        logger.warning(
            "Trusted client public key '%s' not found. Generating a new one for testing.",
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
            logger.info(
                "Generated and saved new trusted client public key to '%s'.", filename
            )
        except Exception as e:
            logger.error("Error saving trusted client public key: %s", e)
            raise
        return temp_public_key


class Server:
    def __init__(self) -> None:
        self.connected_clients: set[websockets.WebSocketServerProtocol] = set()
        self.saved_key: Optional[bytes] = None
        self.saved_salt: Optional[bytes] = None
        self.static_private_key, self.static_public_key = (
            load_or_generate_server_static_keys()
        )
        pem_public = self.static_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        logger.info("Server static public key (PEM):\n%s", pem_public.decode())
        self.trusted_client_public_key = load_or_generate_trusted_client_public_key()

    @staticmethod
    async def send_data(
        websocket: websockets.WebSocketServerProtocol,
        data: bytes,
        data_type: str,
        *,
        signing_key: Ed448PrivateKey,
        salt: Optional[bytes] = None,
    ) -> None:
        logger.debug("Sending [%s]: %s", data_type, data)
        message = {
            "type": data_type,
            "data": base64.b85encode(data).decode(),
        }
        if salt is not None:
            message["salt"] = base64.b85encode(salt).decode()
        payload_bytes = canonical_pack(message)
        signature = sign_data(signing_key, payload_bytes)
        message["signature"] = base64.b85encode(signature).decode()
        packed_message = canonical_pack(message)
        await websocket.send(packed_message)

    async def handle_client(
        self, websocket: websockets.WebSocketServerProtocol, path: str
    ) -> None:
        self.connected_clients.add(websocket)
        logger.info("New client connected.")
        try:
            async for message in websocket:
                logger.debug("Message received.")
                try:
                    message_data = msgpack.unpackb(message, raw=False)
                    signature_b64 = message_data.get("signature")
                    if not signature_b64:
                        logger.warning("No signature in message; discarding.")
                        continue
                    signature = base64.b85decode(signature_b64)
                    message_copy = dict(message_data)
                    message_copy.pop("signature", None)
                    payload_bytes = canonical_pack(message_copy)
                    if not verify_data(
                        self.trusted_client_public_key, signature, payload_bytes
                    ):
                        logger.warning(
                            "Signature verification failed; discarding message."
                        )
                        continue
                    msg_type = message_data.get("type")
                    if msg_type == "key":
                        await self.handle_key_message(websocket, message_data)
                    elif msg_type == "message":
                        await self.handle_text_message(websocket, message_data)
                    else:
                        logger.warning("Invalid message type received: %s", msg_type)
                except Exception as e:
                    logger.error("Error processing message: %s", e)
        except Exception as e:
            logger.error("Client connection error: %s", e)
        finally:
            self.connected_clients.remove(websocket)
            logger.info("Client disconnected.")
            if not self.connected_clients:
                self.saved_key = None
                self.saved_salt = None

    async def handle_key_message(
        self, websocket: websockets.WebSocketServerProtocol, message_data: dict
    ) -> None:
        try:
            received_key = base64.b85decode(message_data["data"])
            received_salt = base64.b85decode(message_data["salt"])
            logger.info("Received key: %s with salt: %s", received_key, received_salt)
            if self.saved_key is None and self.saved_salt is None:
                self.saved_key = received_key
                self.saved_salt = received_salt
            else:
                combined_salt = received_salt + self.saved_salt
                await self.send_data(
                    websocket,
                    self.saved_key,
                    "key",
                    salt=combined_salt,
                    signing_key=self.static_private_key,
                )
                await self.broadcast_data(
                    data=received_key,
                    data_type="key",
                    salt=combined_salt,
                    exclude={websocket},
                )
        except Exception as e:
            logger.error("Error handling key message: %s", e)

    async def handle_text_message(
        self, websocket: websockets.WebSocketServerProtocol, message_data: dict
    ) -> None:
        try:
            received_message = base64.b85decode(message_data["data"])
            if len(self.connected_clients) < 2:
                logger.info("Waiting for another client to connect...")
                return
            await self.broadcast_data(
                data=received_message,
                data_type="message",
                exclude={websocket},
            )
        except Exception as e:
            logger.error("Error handling text message: %s", e)

    async def broadcast_data(
        self,
        data: bytes,
        data_type: str,
        *,
        signing_key: Optional[Ed448PrivateKey] = None,
        salt: Optional[bytes] = None,
        exclude: set[websockets.WebSocketServerProtocol] = set(),
    ) -> None:
        if signing_key is None:
            signing_key = self.static_private_key
        tasks = [
            self.send_data(client, data, data_type, salt=salt, signing_key=signing_key)
            for client in self.connected_clients
            if client not in exclude
        ]
        if tasks:
            await asyncio.gather(*tasks)

    async def start(self) -> None:
        async with websockets.serve(self.handle_client, "0.0.0.0", 4448):
            logger.info("Server initialized on ws://0.0.0.0:4448")
            await asyncio.Future()


async def main() -> None:
    server = Server()
    await server.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server shutdown requested by user.")
