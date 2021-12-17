import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # Check password if it exists in APU response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    res = request_api_data(first5_char)
    return int(get_password_leaks_count(res, tail))


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'The password \"{password}\" has been leaked {count} times')
        else:
            print('That password has not been leaked')


if __name__ == '__main__':
    main(sys.argv[1:])
