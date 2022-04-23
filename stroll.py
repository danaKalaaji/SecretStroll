"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple

# Optional import
from serialization import jsonpickle
from credential import *

# Type aliases
State = Any


def jencode(to_encode):
    return jsonpickle.encode(to_encode).encode()


def jdecode(to_decode):
    return jsonpickle.decode(to_decode)


class Server:
    """Server"""


    def __init__(self):
        """
        Server constructor.
        """
        return


    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's pubic information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """

        # Note that `server.py` appends "username" to the command line attributes
        sk, pk = generate_key(subscriptions+['sk'])

        return jencode(sk), jencode((pk, subscriptions))


    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        user_subscriptions = subscriptions
        server_sk = jdecode(server_sk)
        server_pk, subscriptions = jdecode(server_pk)

        issuance_request = jdecode(issuance_request)

        # Note that `server.py` appends "username" to the command line attributes, so "username" is in "subscriptions"
        issuer_attributes = {att:b'0' for att in subscriptions if att not in user_subscriptions and att != 'username'}

        response = sign_issue_request(server_sk, server_pk, issuance_request, issuer_attributes) # returns null

        return jencode(response)


    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        server_pk, subscriptions = jdecode(server_pk)
        signature = jdecode(signature)

        disclosed_attributes = signature[1]
        disclosed_attributes_values = signature[2]

        for att in revealed_attributes:
            if disclosed_attributes_values[disclosed_attributes.index(att)] != b'1':
                return False

        return verify_disclosure_proof(server_pk, signature, message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        self.sk, self.pk = generate_key(["foo", "bar"])


    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        user_subscriptions = subscriptions
        server_pk, subscriptions = jdecode(server_pk)

        if not all([subscription in subscriptions for subscription in user_subscriptions]):
            raise ValueError("User can only subscribe to available subscriptions")

        user_attributes = {att:b'1' for att in user_subscriptions}
        user_attributes['sk'] = jencode(self.sk)
        user_attributes['username'] = b'1' #jencode(username)

        request, t = create_issue_request(server_pk, user_attributes)

        return (jencode(request), (t, user_attributes))


    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        server_pk, subscriptions = jdecode(server_pk)
        server_response = jdecode(server_response)
        t, user_attributes = private_state

        credentials = obtain_credential(server_pk, server_response, user_attributes, t)

        return jencode(credentials)


    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        server_pk, subscriptions = jdecode(server_pk)
        credentials = jdecode(credentials)

        hidden_attributes = [att for att in subscriptions if att not in types and att != 'username']
        hidden_attributes.append('sk')

        disclosure_proof = create_disclosure_proof(server_pk, credentials, hidden_attributes, message)

        return jencode(disclosure_proof)