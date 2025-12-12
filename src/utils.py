"""
Utility Functions for Private Set-Membership Test Protocol

This module provides utility functions for polynomial operations used in the
private set-membership test protocol. The key operation is expanding a polynomial
from its root form to standard coefficient form.

Given roots r_1, r_2, ..., r_n, we expand:
    P(x) = (x - r_1)(x - r_2)...(x - r_n)
into standard form:
    P(x) = a_n * x^n + a_{n-1} * x^{n-1} + ... + a_1 * x + a_0

This expansion is crucial because Paillier encryption only supports additive
homomorphism, and the standard form allows us to compute P(c) using only:
    - Scalar multiplication: E(c^i)^{a_i} = E(a_i * c^i)
    - Homomorphic addition: E(m_1) * E(m_2) = E(m_1 + m_2)
"""

from typing import List
import numpy as np


def expand_polynomial(roots: List[int]) -> List[int]:
    """
    Expand a polynomial from root form to standard coefficient form.

    Given roots [r_1, r_2, ..., r_n], computes coefficients [a_0, a_1, ..., a_n]
    such that:
        (x - r_1)(x - r_2)...(x - r_n) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n

    Algorithm:
        Start with P(x) = 1 (coefficients = [1])
        For each root r_i:
            Multiply current polynomial by (x - r_i)
            This is done by: new_coeffs = coeffs * x - coeffs * r_i

    Args:
        roots: List of polynomial roots [r_1, r_2, ..., r_n]
               These are the elements of the server's dataset S

    Returns:
        List of coefficients [a_0, a_1, ..., a_n] where:
            - a_0 is the constant term
            - a_n is the leading coefficient (always 1 for monic polynomial)
            - Length is len(roots) + 1

    Example:
        >>> expand_polynomial([1, 2, 3])  # (x-1)(x-2)(x-3)
        [-6, 11, -6, 1]  # -6 + 11x - 6x^2 + x^3

        Verification: (x-1)(x-2)(x-3) = x^3 - 6x^2 + 11x - 6

    Note:
        The coefficients can become very large for large datasets.
        Python handles arbitrary precision integers natively.
    """
    if not roots:
        # Empty set: P(x) = 1 (constant polynomial)
        # Any query c will give P(c) = 1 != 0, so c not in empty set
        return [1]

    # Start with P(x) = 1, represented as [1]
    # coeffs[i] represents the coefficient of x^i
    coeffs = [1]

    for root in roots:
        # Multiply current polynomial by (x - root)
        # If P(x) = sum(coeffs[i] * x^i), then
        # P(x) * (x - root) = P(x) * x - P(x) * root
        #                   = sum(coeffs[i] * x^{i+1}) - sum(coeffs[i] * root * x^i)

        # New polynomial has degree one higher
        new_coeffs = [0] * (len(coeffs) + 1)

        # Add coeffs[i] * x^{i+1} term (shift coefficients up)
        for i in range(len(coeffs)):
            new_coeffs[i + 1] += coeffs[i]

        # Subtract coeffs[i] * root * x^i term
        for i in range(len(coeffs)):
            new_coeffs[i] -= root * coeffs[i]

        coeffs = new_coeffs

    return coeffs


def expand_polynomial_numpy(roots: List[int]) -> List[int]:
    """
    Alternative implementation using NumPy's polynomial functions.

    This provides a more efficient implementation for large datasets,
    though it may have precision issues for very large coefficients.

    Args:
        roots: List of polynomial roots

    Returns:
        List of coefficients [a_0, a_1, ..., a_n]

    Note:
        NumPy's poly function returns coefficients in descending order
        (highest degree first), so we reverse the result.
    """
    if not roots:
        return [1]

    # np.poly computes coefficients of (x - r_1)(x - r_2)...
    # Returns in descending order: [a_n, a_{n-1}, ..., a_1, a_0]
    coeffs_descending = np.poly(roots)

    # Convert to integers and reverse to ascending order
    coeffs_ascending = [int(round(c)) for c in reversed(coeffs_descending)]

    return coeffs_ascending


def evaluate_polynomial(coeffs: List[int], x: int) -> int:
    """
    Evaluate polynomial at a given point using Horner's method.

    Given coefficients [a_0, a_1, ..., a_n] and value x,
    computes: a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n

    Uses Horner's method for efficiency:
        P(x) = a_0 + x*(a_1 + x*(a_2 + ... + x*(a_{n-1} + x*a_n)...))

    This reduces the number of multiplications from O(n^2) to O(n).

    Args:
        coeffs: Polynomial coefficients [a_0, a_1, ..., a_n] in ascending order
        x: Point at which to evaluate the polynomial

    Returns:
        The value P(x) = sum(coeffs[i] * x^i)

    Example:
        >>> evaluate_polynomial([-6, 11, -6, 1], 2)  # P(2) where P(x) = (x-1)(x-2)(x-3)
        0  # Because 2 is a root

        >>> evaluate_polynomial([-6, 11, -6, 1], 4)
        6  # 4 is not a root: (4-1)(4-2)(4-3) = 3*2*1 = 6
    """
    if not coeffs:
        return 0

    # Horner's method: start from highest degree coefficient
    # P(x) = a_0 + x*(a_1 + x*(a_2 + ... + x*a_n))
    result = coeffs[-1]  # Start with a_n (highest degree)

    # Work backwards through coefficients
    for i in range(len(coeffs) - 2, -1, -1):
        result = result * x + coeffs[i]

    return result


def compute_powers(base: int, max_power: int) -> List[int]:
    """
    Compute all powers of a base up to a maximum power.

    Computes [base^0, base^1, base^2, ..., base^max_power]

    Args:
        base: The base value
        max_power: Maximum power to compute (inclusive)

    Returns:
        List of powers [1, base, base^2, ..., base^max_power]

    Example:
        >>> compute_powers(3, 4)
        [1, 3, 9, 27, 81]
    """
    powers = []
    current = 1

    for _ in range(max_power + 1):
        powers.append(current)
        current *= base

    return powers


def verify_polynomial_expansion(roots: List[int], coeffs: List[int]) -> bool:
    """
    Verify that the expanded coefficients correctly represent the polynomial.

    Tests that P(r) = 0 for all roots r, and P(x) != 0 for some non-roots.

    Args:
        roots: Original polynomial roots
        coeffs: Expanded coefficients to verify

    Returns:
        True if verification passes, False otherwise
    """
    # Check that all roots give P(r) = 0
    for root in roots:
        if evaluate_polynomial(coeffs, root) != 0:
            return False

    # Check that some non-roots give P(x) != 0
    # Test a few values that are not roots
    test_values = set(range(-10, 11)) - set(roots)
    non_zero_found = False

    for x in list(test_values)[:5]:  # Test up to 5 non-roots
        if evaluate_polynomial(coeffs, x) != 0:
            non_zero_found = True
            break

    # For non-empty root sets, we should find non-zero values
    if roots and not non_zero_found:
        return False

    return True
