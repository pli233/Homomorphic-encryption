# Private Set-Membership Test Protocol

A privacy-preserving set membership test implementation using Paillier homomorphic encryption for CS1640 AI & Security.

## Overview

This project implements a protocol where:
- **Client** has a private query value `c`
- **Server** has a private dataset `S = {s₁, s₂, ..., sₙ}`
- Client learns whether `c ∈ S` without revealing `c` to Server
- Server's dataset `S` remains private from Client

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the demo
python demo.py
```

## License

MIT License