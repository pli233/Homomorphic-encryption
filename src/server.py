"""
Server Implementation for Private Set-Membership Test Protocol

The Server holds a private dataset S = {s_1, s_2, ..., s_n} and processes
queries from Clients to determine membership without revealing S.

Protocol Steps (Server Side):
    Step 2: Compute polynomial coefficients and evaluate E(P_S(c)) homomorphically
    Step 3: Blind the result and send back to Client

Key Insight:
    The membership polynomial P_S(x) = (x - s_1)(x - s_2)...(x - s_n) has the property:
    - P_S(c) = 0 if and only if c is in S

Security Properties:
    - The Client never learns S (only the blinded result r * P_S(c))
    - The blinding factor r prevents the Client from learning P_S(c) when c is not in S
"""

from dataclasses import dataclass
from typing import List
import secrets
import phe
from phe import paillier

from .utils import expand_polynomial
from .client import ClientMessage, ServerMessage


class Server:
    """
    Server class for the Private Set-Membership Test Protocol.

    The Server pre-computes the coefficients of the membership polynomial
    P_S(x) from its dataset S, then uses homomorphic operations to evaluate
    P_S at the Client's encrypted query value.

    Attributes:
        dataset: The private dataset S = {s_1, s_2, ..., s_n}
        coefficients: Pre-computed polynomial coefficients [a_0, a_1, ..., a_n]
                     where P_S(x) = a_0 + a_1*x + ... + a_n*x^n

    Example:
        >>> server = Server(dataset=[1, 2, 3, 4, 5])
        >>> response = server.process_query(client_message)
        >>> # Send response back to client
    """

    def __init__(self, dataset: List[int]) -> None:
        """
        Initialize the Server with a private dataset.

        Pre-computes the polynomial coefficients by expanding:
            P_S(x) = (x - s_1)(x - s_2)...(x - s_n)
        into standard form:
            P_S(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n

        Args:
            dataset: List of integers representing the private dataset S
                    Duplicates are automatically removed

        Note:
            The polynomial computation is done once at initialization,
            making subsequent queries efficient.
        """
        # Remove duplicates and store as list
        self.dataset = list(set(dataset))
        self._size = len(self.dataset)

        # Pre-compute polynomial coefficients
        # P_S(x) = (x - s_1)(x - s_2)...(x - s_n) expanded to [a_0, a_1, ..., a_n]
        self.coefficients = self._compute_polynomial_coefficients()

    def _compute_polynomial_coefficients(self) -> List[int]:
        """
        Expand the membership polynomial to standard coefficient form.

        Converts P_S(x) = (x - s_1)(x - s_2)...(x - s_n)
        to [a_0, a_1, ..., a_n] where P_S(x) = sum(a_i * x^i)

        Returns:
            List of polynomial coefficients in ascending order of degree

        Example:
            For dataset S = {1, 2, 3}:
            P_S(x) = (x-1)(x-2)(x-3) = x^3 - 6x^2 + 11x - 6
            Returns: [-6, 11, -6, 1]
        """
        return expand_polynomial(self.dataset)

    def _generate_blinding_factor(self) -> int:
        """
        Generate a cryptographically secure random non-zero blinding factor.

        The blinding factor r is used to compute E(r * P_S(c)) instead of
        E(P_S(c)), which prevents the Client from learning the actual value
        of P_S(c) when c is not in S.

        Returns:
            Random non-zero integer suitable for blinding

        Security Note:
            Uses secrets module for cryptographically secure randomness.
            The factor must be non-zero to preserve the zero/non-zero property.
        """
        # Generate a random integer in range [1, 2^128)
        # This provides sufficient entropy for blinding
        while True:
            r = secrets.randbelow(2**128)
            if r != 0:
                return r

    def process_query(self, client_msg: ClientMessage) -> ServerMessage:
        """
        Process a Client's query and return the blinded result (Steps 2 & 3).

        Step 2: Homomorphic Polynomial Evaluation
            Given encrypted powers [E(1), E(c), E(c^2), ..., E(c^n)] and
            coefficients [a_0, a_1, ..., a_n], computes:

            E(P_S(c)) = E(a_0) * E(c)^{a_1} * E(c^2)^{a_2} * ... * E(c^n)^{a_n}
                      = E(a_0 + a_1*c + a_2*c^2 + ... + a_n*c^n)
                      = E(P_S(c))

            Using Paillier homomorphic properties:
            - E(m)^k = E(k*m)  (scalar multiplication)
            - E(m_1) * E(m_2) = E(m_1 + m_2)  (homomorphic addition)

        Step 3: Blinding
            Compute R = E(P_S(c))^r = E(r * P_S(c)) for random non-zero r

        Args:
            client_msg: ClientMessage containing public key and encrypted powers

        Returns:
            ServerMessage containing E(r * P_S(c))

        Raises:
            ValueError: If client message set size doesn't match server's dataset
        """
        # Validate that client provided enough encrypted powers
        if client_msg.set_size != self._size:
            raise ValueError(
                f"Set size mismatch: client expects {client_msg.set_size}, "
                f"server has {self._size}"
            )

        if len(client_msg.encrypted_powers) != self._size + 1:
            raise ValueError(
                f"Expected {self._size + 1} encrypted powers, "
                f"got {len(client_msg.encrypted_powers)}"
            )

        public_key = client_msg.public_key
        encrypted_powers = client_msg.encrypted_powers

        # Step 2: Compute E(P_S(c)) homomorphically
        # E(P_S(c)) = E(sum(a_i * c^i)) = product(E(c^i)^{a_i})

        # Handle the constant term a_0 separately (needs fresh encryption)
        # E(a_0) = E(a_0 * 1) = E(1)^{a_0} = encrypted_powers[0]^{a_0}
        # But we can also just encrypt a_0 directly
        result = public_key.encrypt(self.coefficients[0])

        # Add each term a_i * c^i for i = 1 to n
        for i in range(1, len(self.coefficients)):
            coeff = self.coefficients[i]

            # Skip if coefficient is zero (no contribution)
            if coeff == 0:
                continue

            # Compute E(c^i)^{a_i} = E(a_i * c^i)
            term = encrypted_powers[i] * coeff

            # Add to result: E(result) * E(term) = E(result + term)
            result = result + term

        # Step 3: Blind the result
        # R = E(P_S(c))^r = E(r * P_S(c))
        blinding_factor = self._generate_blinding_factor()
        blinded_result = result * blinding_factor

        return ServerMessage(blinded_result=blinded_result)

    def get_size(self) -> int:
        """
        Get the size of the server's dataset.

        Returns:
            Number of elements in dataset S
        """
        return self._size

    def get_coefficients(self) -> List[int]:
        """
        Get the polynomial coefficients (for debugging/testing).

        Returns:
            List of coefficients [a_0, a_1, ..., a_n]

        Warning:
            This method exposes internal state and should only be
            used for testing. In production, coefficients should
            remain private.
        """
        return self.coefficients.copy()

    def __repr__(self) -> str:
        """String representation of Server."""
        return f"Server(dataset_size={self._size})"

    def __len__(self) -> int:
        """Return the size of the dataset."""
        return self._size
