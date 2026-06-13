import hashlib
import json

from cryptography.fernet import Fernet


DEFAULT_CLIENT_ID = "Client-A"
DEFAULT_SERVER_ID = "Migration-Server-B"


def generate_kerberos_keys():
    client_key = Fernet.generate_key()
    server_key = Fernet.generate_key()

    return client_key, server_key


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_kdc_message(client_id: str, server_id: str, client_key: bytes, server_key: bytes):
    """
    Simulates KDC message generation.

    KDC creates:
    1. Session key
    2. Client part encrypted with client secret key
    3. Service ticket encrypted with server secret key
    """

    session_key = Fernet.generate_key()

    ticket_payload = {
        "client_id": client_id,
        "server_id": server_id,
        "session_key": session_key.decode(),
        "lifetime_seconds": 300,
        "issued_by": "KDC"
    }

    ticket_payload_bytes = json.dumps(ticket_payload, sort_keys=True).encode()

    client_cipher = Fernet(client_key)
    server_cipher = Fernet(server_key)

    client_part = client_cipher.encrypt(ticket_payload_bytes)
    service_ticket = server_cipher.encrypt(ticket_payload_bytes)

    kdc_message = {
        "client_id": client_id,
        "server_id": server_id,
        "client_part": client_part.decode(),
        "service_ticket": service_ticket.decode()
    }

    return json.dumps(kdc_message, sort_keys=True).encode()


def decode_kdc_message(kdc_message: bytes, client_key: bytes, server_key: bytes):
    """
    Simulates decoding of KDC message.

    Client decodes client_part.
    Server decodes service_ticket.
    """

    kdc_data = json.loads(kdc_message.decode())

    client_cipher = Fernet(client_key)
    server_cipher = Fernet(server_key)

    client_payload = client_cipher.decrypt(kdc_data["client_part"].encode())
    server_payload = server_cipher.decrypt(kdc_data["service_ticket"].encode())

    return client_payload, server_payload


def kerberos_total_authentication_flow(
    message: bytes,
    client_key: bytes,
    server_key: bytes,
    client_id: str = DEFAULT_CLIENT_ID,
    server_id: str = DEFAULT_SERVER_ID
):
    """
    Simulates total Kerberos authentication communication.

    Steps:
    1. KDC generates encrypted message/ticket
    2. Client decodes client part
    3. Client creates authenticator using session key
    4. Server decodes service ticket
    5. Server verifies authenticator against the message hash
    """

    kdc_message = generate_kdc_message(client_id, server_id, client_key, server_key)
    kdc_data = json.loads(kdc_message.decode())

    client_cipher = Fernet(client_key)
    server_cipher = Fernet(server_key)

    client_payload = client_cipher.decrypt(kdc_data["client_part"].encode())
    client_payload_data = json.loads(client_payload.decode())

    session_key = client_payload_data["session_key"].encode()
    session_cipher = Fernet(session_key)

    authenticator_data = {
        "client_id": client_id,
        "message_hash": sha256_hex(message),
        "auth_status": "Client authenticated using Kerberos session key"
    }

    authenticator = session_cipher.encrypt(
        json.dumps(authenticator_data, sort_keys=True).encode()
    )

    server_payload = server_cipher.decrypt(kdc_data["service_ticket"].encode())
    server_payload_data = json.loads(server_payload.decode())

    server_session_key = server_payload_data["session_key"].encode()
    server_session_cipher = Fernet(server_session_key)

    decoded_authenticator = server_session_cipher.decrypt(authenticator)
    decoded_authenticator_data = json.loads(decoded_authenticator.decode())

    return decoded_authenticator_data["message_hash"] == sha256_hex(message)
