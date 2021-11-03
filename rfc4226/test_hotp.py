#!/usr/bin/env python
# HOTP Test Scenarios
# Refer here for test vectors: https://datatracker.ietf.org/doc/html/rfc4226

import pytest
import rfc4226.hotp as hotp

# test vectors
secret_key = "3132333435363738393031323334353637383930"
secret_bytes = bytes.fromhex(secret_key)
test_vectors = {
            0: 755224,
            1: 287082,
            2: 359152,
            3: 969429,
            4: 338314,
            5: 254676,
            6: 287922,
            7: 162583,
            8: 399871,
            9: 520489
        }

# Test Exception Handling
def test_DT_runtime_error() -> bool:
    integer_value = 1234
    with pytest.raises(RuntimeError):
        hotp.DT(integer_value)


def test_modulo_error_invalid_input_type() -> bool:
    string_value = "Wrong_Input"
    with pytest.raises(RuntimeError):
        hotp.modulo(string_value)


def test_modulo_error_invalid_token_len() -> bool:
    int_value = 255
    with pytest.raises(RuntimeError):
        hotp.modulo(b'input', int_value)


# HOTP codes generation tests
def test_hmac_codes_generation() -> bool:
    for k, v in test_vectors.items():
        z = hotp.HOTP(secret_bytes, k)
        assert z == v
