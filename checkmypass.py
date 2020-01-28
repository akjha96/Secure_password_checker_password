import requests
import hashlib
import sys


def request_api_data(query_char):
    """
    This method will fetch us all the hashed passwords and the no. of times its been breached.
    :param query_char: first 5 char of hashed password
    :return: res
    """
    # THis is url for api we are using
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    # res will store the data gathered using api via requests.get method
    res = requests.get(url)
    # Check what is the status code of res: 200 is ok
    if res.status_code != 200:
        # raise Runtime error if res's status code is NOT OK i.e., 200
        raise RuntimeError(f'Error fetching {res.status_code}, check api and try again!')
    #  if all is good till here, Return res
    return res


def get_password_leaks_count(hashes, hash_to_check):
    """
    this method will return no of times the password has been breached.
    :param hashes: contains all the response from api for that specific first6_chars
    :param hash_to_check: contains rest of the chars from hashed passwords
    :return: no of counts password has been breached.
    """
    # here we are splitting each line  based on ':' to separate hashes and no of times breached
    # we also use hashes.text.splitlines() to get each line and then split based on ':'
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    """
    this function return the response provided via request_api_data by sending the hashed password to the function
    :param password: string
    :return: response
    """
    # Here we have to 1st encode the password to 'utf-8'. Then use  hexdigest() in order to
    # convert the value to hex and then convert whole thing  to uppercase to meet SHA1 standard.
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Now divide the password generated into 2 parts: 1st contains the first 5 chars and 2md the rest
    first5_char, tail = sha1password[:5], sha1password[5:]
    # Next pass the first5_char to request_api_data() to get the desired data
    response = request_api_data(first5_char)
    # return no of times this password ahs been leaked using fn get_password_leaks_count
    return get_password_leaks_count(response, tail)


def main(args):
    """
    This  is our main method that call pwned_api_check fn to check all the passwords supplied.
    :param args: is lust of passwords supplied.
    :return: done when success
    """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"Oops!!! {password} was breached {count} times, Please consider changing it!\n")
        else:
            print(f"Great!!! {password} was NEVER breached! CARRY ONN...\n")

    return 'done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
