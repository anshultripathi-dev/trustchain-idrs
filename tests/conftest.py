"""Keep the suite hermetic: never inherit hardware mode / board IPs from a developer's .env."""
import os

os.environ["TRUSTCHAIN_MODE"] = "sim"
os.environ["TRUSTCHAIN_HOME"] = "core"      # hermetic and fast; the full home has its own tests
os.environ["ESP32_SMART_HOME_IP"] = ""
os.environ["ESP32_SECURITY_IP"] = ""
os.environ["TRUSTCHAIN_ADMIN_TOKEN"] = "admin"
os.environ["TRUSTCHAIN_REAL_ML"] = "0"
