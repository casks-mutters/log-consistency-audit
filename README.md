# log-consistency-audit

Compare `eth_getLogs` results across two RPC providers and produce a Keccak
commitment over the log set.

Useful for:

- Detecting RPCs that drop or mis-index logs
- Verifying L1/L2 / archive-node consistency
- Auditing event history reproducibility

---

## Installation

1. Python 3.9+
2. Install dependencies:

   ```bash
   pip install web3

   
 ## Usage
   
### log_audit.py

### quick_audit.py

### consistency_audit_cli.py
