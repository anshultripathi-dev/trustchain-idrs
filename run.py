"""Start TrustChain-IDRS:  python run.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn  # noqa: E402

from trustchain.config import Settings  # noqa: E402

if __name__ == "__main__":
    s = Settings()
    uvicorn.run("trustchain.api:app", host=s.host, port=s.port, log_level="warning")
