"""
Private Set-Membership Test Protocol Implementation

This package implements a privacy-preserving set membership test using
Paillier homomorphic encryption. It allows a client to check if their
private query value exists in a server's private dataset without revealing
either party's private information.

Modules:
    - client: Client-side implementation for query generation and result verification
    - server: Server-side implementation for polynomial evaluation
    - protocol: High-level protocol execution logic
    - utils: Utility functions for polynomial operations
"""

from .client import Client, ClientMessage
from .server import Server, ServerMessage
from .protocol import PrivateSetMembershipProtocol
from .utils import expand_polynomial, evaluate_polynomial

__version__ = "1.0.0"
__author__ = "CS1640 AI & Security"

__all__ = [
    "Client",
    "ClientMessage",
    "Server",
    "ServerMessage",
    "PrivateSetMembershipProtocol",
    "expand_polynomial",
    "evaluate_polynomial",
]
