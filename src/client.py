"""
Client Implementation for Private Set-Membership Test Protocol

The Client holds a private query value 'c' and wants to check if c is in
the Server's private dataset S, without revealing c to the Server.

Protocol Steps (Client Side):
    Step 1: Generate Paillier key pair and encrypt powers of c
    Step 4: Decrypt server's response and determine membership

Security Properties:
    - The Server never learns the query value c (semantic security of Paillier)
    - The Client only learns whether c is in S, nothing about other elements
"""

from dataclasses import dataclass
from typing import List, Optional
import phe
from phe import paillier


@dataclass
class ClientMessage:
    """
    Message sent from Client to Server in Step 1.

    Contains the public key and encrypted powers of the query value,
    allowing the Server to compute E(P_S(c)) homomorphically.

    Attributes:
        public_key: Paillier public key for homomorphic operations
        encrypted_powers: List of encrypted values [E(c^0), E(c^1), ..., E(c^n)]
                         where n is the size of the server's dataset
        set_size: Expected size of the server's dataset (degree of polynomial)
    """
    public_key: paillier.PaillierPublicKey
    encrypted_powers: List[paillier.EncryptedNumber]
    set_size: int


@dataclass
class ServerMessage:
    """
    Message sent from Server to Client in Step 3.

    Contains the blinded encrypted polynomial evaluation result.

    Attributes:
        blinded_result: E(r * P_S(c)) where r is a random non-zero blinding factor
    """
    blinded_result: paillier.EncryptedNumber


class Client:
    """
    Client class for the Private Set-Membership Test Protocol.

    The Client generates a Paillier key pair, encrypts powers of their
    private query value, sends them to the Server, and interprets the
    Server's blinded response to determine set membership.

    Attributes:
        query: The private query value c
        set_size: Size of the Server's dataset (needed for polynomial degree)
        public_key: Paillier public key (shared with Server)
        private_key: Paillier private key (kept secret)

    Example:
        >>> client = Client(query=42, set_size=10)
        >>> msg = client.create_message()
        >>> # Send msg to server, receive response
        >>> is_member = client.check_membership(server_response)
    """

    def __init__(
        self,
        query: int,
        set_size: int,
        key_size: int = 1024
    ) -> None:
        """
        Initialize the Client with a query value and generate Paillier keys.

        Args:
            query: The private query value c that Client wants to check
            set_size: Size of the Server's dataset S (determines polynomial degree)
            key_size: Bit length of Paillier modulus n (default 1024)
                     Higher values provide more security but slower computation

        Security Note:
            Key size of 1024 bits provides ~80 bits of security.
            For production use, consider 2048 or 3072 bits.
        """
        self.query = query
        self.set_size = set_size
        self.key_size = key_size

        # Generate Paillier key pair
        # Public key: (n, g) where n = p*q for large primes p, q
        # Private key: (lambda, mu) derived from p, q
        self.public_key, self.private_key = paillier.generate_paillier_keypair(
            n_length=key_size
        )

        # Cache for encrypted powers (computed lazily)
        self._encrypted_powers: Optional[List[paillier.EncryptedNumber]] = None

    def _compute_encrypted_powers(self) -> List[paillier.EncryptedNumber]:
        """
        Compute and encrypt all powers of the query value.

        Computes: [E(c^0), E(c^1), E(c^2), ..., E(c^n)]
        where n = set_size (degree of the membership polynomial)

        The encryption uses fresh randomness for each power, ensuring
        semantic security (identical plaintexts produce different ciphertexts).

        Returns:
            List of encrypted powers [E(1), E(c), E(c^2), ..., E(c^n)]
        """
        encrypted_powers = []
        current_power = 1  # c^0 = 1

        for i in range(self.set_size + 1):
            # Encrypt current power with fresh randomness
            encrypted = self.public_key.encrypt(current_power)
            encrypted_powers.append(encrypted)

            # Compute next power: c^{i+1} = c^i * c
            current_power *= self.query

        return encrypted_powers

    def create_message(self) -> ClientMessage:
        """
        Create the message to send to the Server (Protocol Step 1).

        This message contains:
        - The public key (so Server can perform homomorphic operations)
        - Encrypted powers [E(1), E(c), E(c^2), ..., E(c^n)]
        - The expected set size

        The Server will use these encrypted powers to compute E(P_S(c))
        where P_S is the membership polynomial for dataset S.

        Returns:
            ClientMessage containing public key and encrypted powers

        Security Note:
            The encrypted powers reveal nothing about c due to semantic
            security of Paillier encryption. Each ciphertext is
            computationally indistinguishable from random.
        """
        # Compute encrypted powers if not already cached
        if self._encrypted_powers is None:
            self._encrypted_powers = self._compute_encrypted_powers()

        return ClientMessage(
            public_key=self.public_key,
            encrypted_powers=self._encrypted_powers,
            set_size=self.set_size
        )

    def check_membership(self, server_response: ServerMessage) -> bool:
        """
        Determine if query is in the Server's set (Protocol Step 4).

        Decrypts the Server's blinded result E(r * P_S(c)) to get r * P_S(c).

        Membership Decision:
            - If r * P_S(c) = 0, then P_S(c) = 0, so c is in S
            - If r * P_S(c) != 0, then P_S(c) != 0, so c is not in S

        Args:
            server_response: ServerMessage containing E(r * P_S(c))

        Returns:
            True if query c is in the Server's dataset S
            False otherwise

        Security Note:
            The blinding factor r ensures that when c is not in S,
            the Client only learns that P_S(c) != 0, not its actual value.
            This prevents the Client from gaining information about S.
        """
        # Decrypt the blinded result: D(E(r * P_S(c))) = r * P_S(c)
        blinded_evaluation = self.private_key.decrypt(server_response.blinded_result)

        # c is in S if and only if P_S(c) = 0
        # Since r != 0, we have r * P_S(c) = 0 iff P_S(c) = 0
        return blinded_evaluation == 0

    def get_query(self) -> int:
        """
        Get the client's private query value.

        Returns:
            The query value c

        Warning:
            This method is provided for testing/debugging.
            In a real deployment, the query should remain private.
        """
        return self.query

    def __repr__(self) -> str:
        """String representation of Client."""
        return (
            f"Client(query=***, set_size={self.set_size}, "
            f"key_size={self.key_size})"
        )
