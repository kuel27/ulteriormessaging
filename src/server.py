import asyncio
import base64

import msgpack
import websockets


class Server:
    def __init__(self):
        self.connected_clients = set()
        self.saved_key = None
        self.saved_salt = None

    @staticmethod
    async def send_data(websocket, data, data_type, salt=None):
        print(f"Sending [{data_type}]: {data}\n")

        data_message = {"type": data_type, "data": base64.b85encode(data).decode()}

        if salt is not None:
            data_message["salt"] = base64.b85encode(salt).decode()

        packed_message = msgpack.packb(data_message)
        await websocket.send(packed_message)

    async def handle_client(self, websocket, path):
        self.connected_clients.add(websocket)
        print("New client connected")

        try:
            async for message in websocket:
                print("Message received")

                try:
                    message_data = msgpack.unpackb(message)

                    if message_data["type"] == "key":
                        received_key = base64.b85decode(message_data["data"])
                        received_salt = base64.b85decode(message_data["salt"])

                        print(
                            f"Received key {received_key} with salt {received_salt}\n"
                        )

                        if self.saved_key is None and self.saved_salt is None:
                            self.saved_key = received_key
                            self.saved_salt = received_salt
                        else:
                            await self.send_data(
                                websocket,
                                self.saved_key,
                                "key",
                                received_salt + self.saved_salt,
                            )

                            for client in self.connected_clients:
                                if client != websocket:
                                    await self.send_data(
                                        client,
                                        received_key,
                                        "key",
                                        received_salt + self.saved_salt,
                                    )

                    elif message_data["type"] == "message":
                        received_message = base64.b85decode(message_data["data"])

                        if len(self.connected_clients) < 2:
                            print("Waiting for the other client to connect")
                            continue

                        for client in self.connected_clients:
                            if client != websocket:
                                await self.send_data(
                                    client, received_message, "message"
                                )
                    else:
                        print("Invalid message type")

                except Exception as e:
                    print(f"Error processing message: {str(e)}")

        except Exception as e:
            print(f"Error in client connection: {str(e)}")

        finally:
            self.connected_clients.remove(websocket)
            print("Client disconnected")

    async def start(self):
        async with websockets.serve(self.handle_client, "localhost", 4448):
            print("Server initialized")
            await asyncio.Future()


async def main():
    server = Server()
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
