import base64
import hashlib

from hmac import hmac_sha1

# Define test vectors
test_vectors = [
    {
        'message': b'lab3319',
        'key': b'asdkjfhaslkdjhfalskjdhfaslkjdhflsakdjhfalskjdhflaksjdhfkasjdhfklasjdhfss',
        'expected_hmac': '5792419d37b3b638c45ca25adcc272693d11ed55'
    }
]


# Define a function to run tests
def run_tests():

    with open("Random_number.txt", "r") as random_file:
        random_string = random_file.read().strip()

    with open("password.txt", "r") as password_file:
        shared_password = password_file.read().strip()

    random_number = random_string.encode('utf-8')
    print("\nrandom number:", random_number)

    for i, test_vector in enumerate(test_vectors, 1):
        computed_hmac = hmac_sha1(random_number, shared_password.encode('utf-8'))
        expected_hmac = test_vector['expected_hmac']

        # Ensure to compare HMACs in the same encoding
        # If expected HMAC is in hex format, convert computed HMAC to hex
        computed_hmac_hex = computed_hmac.hex()

        # If expected HMAC is in Base64 format, convert computed HMAC to Base64
        computed_hmac_base64 = base64.b64encode(computed_hmac).strip()

        # Compare
        if computed_hmac_hex == expected_hmac or computed_hmac_base64 == expected_hmac:
            print(f'Test {i}: PASS')
            print(f'\nComputed: {computed_hmac_hex}\nExpected: {expected_hmac}')
        else:
            print(f'Test {i}: FAIL\nComputed: {computed_hmac_hex}\nExpected: {expected_hmac}')


# Run tests
if __name__ == "__main__":
    run_tests()