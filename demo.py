#!/usr/bin/env python3
"""
Private Set-Membership Test Protocol - Interactive Demo

This script demonstrates the privacy-preserving set membership test protocol
using Paillier homomorphic encryption. It shows how a client can determine
if their private query value exists in a server's private dataset without
either party learning the other's private information.

Usage:
    python demo.py

Example Output:
    =====================================================
    Private Set-Membership Test Protocol Demo
    =====================================================

    --- Test Case 1: Query IN the dataset ---
    Server's dataset: [10, 25, 42, 73, 99] (5 elements)
    Client's query: 42
    ...
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.client import Client
from src.server import Server
from src.protocol import PrivateSetMembershipProtocol, run_membership_test
from src.utils import expand_polynomial, evaluate_polynomial


def print_header(title: str) -> None:
    """Print a formatted section header."""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def print_subheader(title: str) -> None:
    """Print a formatted subsection header."""
    print(f"\n--- {title} ---")


def demo_basic_usage() -> None:
    """Demonstrate basic protocol usage."""
    print_header("DEMO 1: Basic Protocol Usage")

    # Define the server's private dataset and client's query
    dataset = [10, 25, 42, 73, 99]
    query = 42

    print(f"\nServer's private dataset: {dataset}")
    print(f"Client's private query: {query}")

    # Run the protocol
    print("\nRunning privacy-preserving membership test...")
    result = run_membership_test(query, dataset, key_size=512, verbose=True)

    print(f"\nResult: {query} {'IS' if result else 'is NOT'} in the dataset")


def demo_step_by_step() -> None:
    """Demonstrate the protocol step by step."""
    print_header("DEMO 2: Step-by-Step Protocol Execution")

    dataset = [5, 15, 25, 35, 45]
    query = 25

    print(f"\nSetup:")
    print(f"  Server's dataset S = {dataset}")
    print(f"  Client's query c = {query}")
    print(f"  Client wants to know: Is {query} in S?")

    # Step 0: Server setup
    print_subheader("Step 0: Server Setup")
    server = Server(dataset)
    coeffs = server.get_coefficients()
    print(f"  Server computes polynomial P_S(x) = (x-5)(x-15)(x-25)(x-35)(x-45)")
    print(f"  Expanded coefficients: {coeffs[:3]}... (truncated)")
    print(f"  Polynomial degree: {len(coeffs) - 1}")

    # Step 1: Client creates message
    print_subheader("Step 1: Client Creates Encrypted Message")
    client = Client(query=query, set_size=server.get_size(), key_size=512)
    client_msg = client.create_message()
    print(f"  Generated Paillier keypair (512-bit for demo)")
    print(f"  Encrypted powers: E(c^0), E(c^1), ..., E(c^{server.get_size()})")
    print(f"  Number of encrypted values: {len(client_msg.encrypted_powers)}")

    # Step 2-3: Server processes query
    print_subheader("Step 2-3: Server Processes Query")
    server_response = server.process_query(client_msg)
    print(f"  Server computes E(P_S(c)) using homomorphic operations")
    print(f"  Server blinds result: E(r * P_S(c)) for random r")
    print(f"  Server sends blinded result to Client")

    # Step 4: Client checks membership
    print_subheader("Step 4: Client Determines Membership")
    is_member = client.check_membership(server_response)
    print(f"  Client decrypts: D(E(r * P_S(c))) = r * P_S(c)")
    print(f"  Result is {'ZERO' if is_member else 'NON-ZERO'}")
    print(f"  Therefore: {query} {'IS' if is_member else 'is NOT'} in S")

    # Verification
    print_subheader("Verification (for demo only)")
    actual_result = evaluate_polynomial(coeffs, query)
    print(f"  Actually computing P_S({query}) = {actual_result}")
    print(f"  Confirms: P_S(c) = 0 means c is in S")


def demo_privacy_properties() -> None:
    """Demonstrate the privacy properties of the protocol."""
    print_header("DEMO 3: Privacy Properties")

    dataset = [100, 200, 300]
    query = 200

    print("\n[Privacy Property 1: Server's view]")
    print("  Server receives: E(c^0), E(c^1), E(c^2), E(c^3)")
    print("  Due to semantic security of Paillier:")
    print("    - Each ciphertext looks like random data")
    print("    - Server cannot distinguish E(200) from E(500)")
    print("    - Server learns NOTHING about the query value c")

    print("\n[Privacy Property 2: Client's view]")
    print("  Client receives: E(r * P_S(c)) where r is random")

    # Run protocol
    server = Server(dataset)
    client = Client(query=query, set_size=server.get_size(), key_size=512)
    client_msg = client.create_message()
    server_response = server.process_query(client_msg)
    decrypted = client.private_key.decrypt(server_response.blinded_result)

    print(f"  Client decrypts to get: {decrypted}")
    print(f"  Since result = 0, Client learns: {query} IS in S")
    print("  BUT Client cannot learn:")
    print("    - What other elements are in S")
    print("    - The size of S (already known from protocol)")
    print("    - The actual polynomial coefficients")

    # Non-member case
    query2 = 150
    client2 = Client(query=query2, set_size=server.get_size(), key_size=512)
    client_msg2 = client2.create_message()
    server_response2 = server.process_query(client_msg2)
    decrypted2 = client2.private_key.decrypt(server_response2.blinded_result)

    print(f"\n  For query {query2} (not in S):")
    print(f"  Client decrypts to get: {decrypted2}")
    print(f"  This is r * P_S({query2}), but r is unknown")
    print(f"  Client only learns: {query2} is NOT in S")
    print("  Client cannot recover P_S(150) without knowing r")


def demo_multiple_queries() -> None:
    """Demonstrate batch queries."""
    print_header("DEMO 4: Multiple Queries (Batch Test)")

    dataset = [1, 2, 3, 4, 5, 10, 20, 30, 40, 50]
    queries = [1, 5, 7, 10, 25, 50]

    print(f"\nDataset: {dataset}")
    print(f"Queries: {queries}")
    print("\nRunning batch membership tests...")

    protocol = PrivateSetMembershipProtocol(key_size=512)
    results = protocol.batch_test(queries, dataset)

    print("\nResults:")
    print("-" * 40)
    for query, result in zip(queries, results):
        status = "MEMBER" if result.is_member else "NOT MEMBER"
        print(f"  Query {query:3d}: {status:12s} ({result.execution_time:.3f}s)")

    members = [q for q, r in zip(queries, results) if r.is_member]
    print(f"\nMembers found: {members}")


def demo_polynomial_math() -> None:
    """Demonstrate the polynomial mathematics."""
    print_header("DEMO 5: Polynomial Mathematics")

    # Simple example
    roots = [1, 2, 3]
    print(f"\nDataset S = {roots}")
    print(f"Membership polynomial: P_S(x) = (x-1)(x-2)(x-3)")

    coeffs = expand_polynomial(roots)
    print(f"\nExpanded form: P_S(x) = {coeffs[3]}x^3 + ({coeffs[2]})x^2 + {coeffs[1]}x + ({coeffs[0]})")
    print(f"Simplified: P_S(x) = x^3 - 6x^2 + 11x - 6")

    print("\nEvaluations:")
    for x in [0, 1, 2, 3, 4, 5]:
        val = evaluate_polynomial(coeffs, x)
        in_set = "IN S" if val == 0 else "not in S"
        print(f"  P_S({x}) = {val:6d}  ->  {x} is {in_set}")

    print("\nKey insight:")
    print("  P_S(c) = 0  <=>  c is a root  <=>  c is in S")


def demo_performance() -> None:
    """Demonstrate performance with timing."""
    print_header("DEMO 6: Performance Analysis")

    sizes = [5, 10, 20]

    print("\nTiming for different dataset sizes (512-bit keys for demo):")
    print("-" * 60)
    print(f"{'Size':>6s}  {'Total (s)':>10s}  {'Server (s)':>11s}  {'Client (s)':>11s}")
    print("-" * 60)

    for size in sizes:
        dataset = list(range(size))
        query = size // 2  # Query middle element (will be member)

        protocol = PrivateSetMembershipProtocol(key_size=512)
        result, timings = protocol.run_with_timings(query, dataset)

        print(f"{size:>6d}  {timings.total:>10.3f}  {timings.server_computation:>11.3f}  "
              f"{timings.client_decryption:>11.3f}")

    print("-" * 60)
    print("\nNote: Actual deployment should use 2048-bit keys for security.")
    print("Larger keys increase computation time significantly.")


def main() -> None:
    """Run all demos."""
    print("\n" + "=" * 60)
    print("   PRIVATE SET-MEMBERSHIP TEST PROTOCOL")
    print("   Interactive Demonstration")
    print("=" * 60)

    print("\nThis demo showcases a privacy-preserving protocol that allows")
    print("a Client to check if their query value is in a Server's dataset")
    print("without revealing the query to the Server or learning the dataset.")

    try:
        demo_basic_usage()
        demo_step_by_step()
        demo_privacy_properties()
        demo_polynomial_math()
        demo_multiple_queries()
        demo_performance()

        print_header("DEMO COMPLETE")
        print("\nThe protocol successfully preserves privacy for both parties!")
        print("\nTo run your own tests:")
        print("  from src.protocol import run_membership_test")
        print("  result = run_membership_test(query=42, dataset=[1, 42, 100])")

    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
