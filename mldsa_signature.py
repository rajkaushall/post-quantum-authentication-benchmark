from dilithium_py.ml_dsa import ML_DSA_65


def generate_mldsa_keys():
    return ML_DSA_65.keygen()


def mldsa_sign_message(secret_key: bytes, message: bytes):
    return ML_DSA_65.sign(secret_key, message)


def mldsa_verify_signature(public_key: bytes, message: bytes, signature: bytes):
    return ML_DSA_65.verify(public_key, message, signature)


def mldsa_total_authentication_flow(public_key: bytes, secret_key: bytes, message: bytes):
    signature = mldsa_sign_message(secret_key, message)
    return mldsa_verify_signature(public_key, message, signature)


def verify_mldsa_correctness(public_key: bytes, secret_key: bytes, message: bytes):
    signature = mldsa_sign_message(secret_key, message)
    valid_original = mldsa_verify_signature(public_key, message, signature)
    valid_tampered = mldsa_verify_signature(public_key, message + b" tampered", signature)

    if not valid_original or valid_tampered:
        raise RuntimeError("ML-DSA verification/tamper check failed.")

    return valid_original, valid_tampered
