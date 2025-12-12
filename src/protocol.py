"""
Protocol Execution Logic for Private Set-Membership Test

This module provides high-level functions for executing the complete
private set-membership test protocol. It orchestrates the interaction
between Client and Server components.

Protocol Overview:
    1. Client creates message with encrypted powers of query
    2. Server evaluates membership polynomial homomorphically
    3. Server blinds result and sends to Client
    4. Client decrypts and determines membership

The protocol ensures:
    - Server never learns the query value c
    - Client never learns the dataset S (only membership result)
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple
import time

from .client import Client, ClientMessage, ServerMessage
from .server import Server


@dataclass
class ProtocolResult:
    """
    Result of the private set-membership test protocol.

    Attributes:
        is_member: True if query is in the dataset, False otherwise
        query: The query value (included for verification in tests)
        dataset_size: Size of the server's dataset
        execution_time: Total protocol execution time in seconds
    """
    is_member: bool
    query: int
    dataset_size: int
    execution_time: float


@dataclass
class ProtocolTimings:
    """
    Detailed timing breakdown of protocol execution.

    Attributes:
        key_generation: Time to generate Paillier keypair
        client_encryption: Time to encrypt powers of query
        server_computation: Time for homomorphic polynomial evaluation
        client_decryption: Time to decrypt and check result
        total: Total protocol execution time
    """
    key_generation: float
    client_encryption: float
    server_computation: float
    client_decryption: float
    total: float


class PrivateSetMembershipProtocol:
    """
    High-level protocol executor for private set-membership tests.

    This class provides convenient methods for running the complete
    protocol, with optional timing information and result verification.

    Example:
        >>> protocol = PrivateSetMembershipProtocol()
        >>> result = protocol.run(query=42, dataset=[1, 2, 3, 42, 100])
        >>> print(f"Is 42 in the set? {result.is_member}")
        Is 42 in the set? True
    """

    def __init__(self, key_size: int = 1024) -> None:
        """
        Initialize the protocol with specified security parameters.

        Args:
            key_size: Bit length for Paillier modulus (default 1024)
                     Higher values provide more security but slower execution
        """
        self.key_size = key_size

    def run(
        self,
        query: int,
        dataset: List[int],
        verbose: bool = False
    ) -> ProtocolResult:
        """
        Execute the complete private set-membership test protocol.

        This method handles all four protocol steps:
        1. Client initialization and message creation
        2. Server processing of encrypted query
        3. (Implicit in step 2) Server blinds and sends response
        4. Client decrypts and determines membership

        Args:
            query: The private query value c
            dataset: The server's private dataset S
            verbose: If True, print progress information

        Returns:
            ProtocolResult containing membership decision and metadata

        Example:
            >>> protocol = PrivateSetMembershipProtocol()
            >>> result = protocol.run(5, [1, 2, 3, 4, 5])
            >>> result.is_member
            True
        """
        start_time = time.time()

        if verbose:
            print(f"Starting private set-membership test protocol")
            print(f"  Dataset size: {len(set(dataset))}")
            print(f"  Key size: {self.key_size} bits")

        # Initialize server with dataset
        server = Server(dataset)
        dataset_size = server.get_size()

        if verbose:
            print(f"  Polynomial degree: {dataset_size}")

        # Initialize client with query
        client = Client(
            query=query,
            set_size=dataset_size,
            key_size=self.key_size
        )

        if verbose:
            print("Step 1: Client creating encrypted message...")

        # Step 1: Client creates message
        client_message = client.create_message()

        if verbose:
            print("Step 2-3: Server processing query and blinding result...")

        # Steps 2-3: Server processes query
        server_response = server.process_query(client_message)

        if verbose:
            print("Step 4: Client checking membership...")

        # Step 4: Client checks membership
        is_member = client.check_membership(server_response)

        execution_time = time.time() - start_time

        if verbose:
            print(f"Protocol complete in {execution_time:.3f} seconds")
            print(f"Result: Query {'IS' if is_member else 'is NOT'} in the dataset")

        return ProtocolResult(
            is_member=is_member,
            query=query,
            dataset_size=dataset_size,
            execution_time=execution_time
        )

    def run_with_timings(
        self,
        query: int,
        dataset: List[int]
    ) -> Tuple[ProtocolResult, ProtocolTimings]:
        """
        Execute the protocol with detailed timing breakdown.

        Useful for performance analysis and benchmarking.

        Args:
            query: The private query value c
            dataset: The server's private dataset S

        Returns:
            Tuple of (ProtocolResult, ProtocolTimings)
        """
        total_start = time.time()

        # Initialize server (includes polynomial computation)
        server = Server(dataset)
        dataset_size = server.get_size()

        # Key generation timing
        key_gen_start = time.time()
        public_key, private_key = Client(
            query=0, set_size=1, key_size=self.key_size
        ).public_key, None
        key_gen_time = time.time() - key_gen_start

        # Full client initialization
        client_start = time.time()
        client = Client(
            query=query,
            set_size=dataset_size,
            key_size=self.key_size
        )
        client_message = client.create_message()
        client_time = time.time() - client_start

        # Server computation
        server_start = time.time()
        server_response = server.process_query(client_message)
        server_time = time.time() - server_start

        # Client decryption
        decrypt_start = time.time()
        is_member = client.check_membership(server_response)
        decrypt_time = time.time() - decrypt_start

        total_time = time.time() - total_start

        result = ProtocolResult(
            is_member=is_member,
            query=query,
            dataset_size=dataset_size,
            execution_time=total_time
        )

        timings = ProtocolTimings(
            key_generation=key_gen_time,
            client_encryption=client_time - key_gen_time,
            server_computation=server_time,
            client_decryption=decrypt_time,
            total=total_time
        )

        return result, timings

    def batch_test(
        self,
        queries: List[int],
        dataset: List[int],
        verbose: bool = False
    ) -> List[ProtocolResult]:
        """
        Run multiple membership tests with the same dataset.

        Note: Each query is a separate protocol execution with fresh
        encryption. The server's polynomial is reused for efficiency.

        Args:
            queries: List of query values to test
            dataset: The server's private dataset S
            verbose: If True, print progress information

        Returns:
            List of ProtocolResult for each query
        """
        results = []
        server = Server(dataset)
        dataset_size = server.get_size()

        for i, query in enumerate(queries):
            if verbose:
                print(f"Testing query {i+1}/{len(queries)}: {query}")

            start_time = time.time()

            # Create fresh client for each query
            client = Client(
                query=query,
                set_size=dataset_size,
                key_size=self.key_size
            )

            # Execute protocol
            client_message = client.create_message()
            server_response = server.process_query(client_message)
            is_member = client.check_membership(server_response)

            execution_time = time.time() - start_time

            results.append(ProtocolResult(
                is_member=is_member,
                query=query,
                dataset_size=dataset_size,
                execution_time=execution_time
            ))

        return results


def run_membership_test(
    query: int,
    dataset: List[int],
    key_size: int = 1024,
    verbose: bool = False
) -> bool:
    """
    Convenience function to run a single membership test.

    This is the simplest way to use the protocol.

    Args:
        query: Value to check for membership
        dataset: Dataset to check against
        key_size: Paillier key size in bits
        verbose: Print progress information

    Returns:
        True if query is in dataset, False otherwise

    Example:
        >>> run_membership_test(42, [1, 42, 100])
        True
        >>> run_membership_test(5, [1, 42, 100])
        False
    """
    protocol = PrivateSetMembershipProtocol(key_size=key_size)
    result = protocol.run(query, dataset, verbose=verbose)
    return result.is_member
