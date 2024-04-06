
import requests  # This library allows Python code to send HTTP requests easily. In this code, it's used to make requests to an external API.
import hashlib   #This library provides various hash functions, such as SHA-1, which are used to securely hash data.
import sys      # This module provides access to some variables used or maintained by the Python interpreter and to functions that interact strongly with the interpreter.

def request_api_data(query_char):
  url = 'https://api.pwnedpasswords.com/range/' + query_char  #This function takes a query_char parameter, which represents the first five characters of a SHA-1 hash of a password.
  res = requests.get(url) #It constructs a URL using the provided query_char and sends an HTTP GET request to the Have I Been Pwned API.
  if res.status_code != 200:
    raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
  return res
#If the request is successful (status code 200), it returns the response; otherwise, it raises a RuntimeError with an error message.

def get_password_leaks_count(hashes, hash_to_check):
  hashes = (line.split(':') for line in hashes.text.splitlines())
  for h, count in hashes:
    if h == hash_to_check:
      return count
  return 0
# It splits the response into lines and then splits each line into a hash and a count. It then iterates through these hash-count pairs.
# If it finds a match for hash_to_check, it returns the corresponding count. If no match is found, it returns 0.

def pwned_api_check(password):
  sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  first5_char, tail = sha1password[:5], sha1password[5:]
  response = request_api_data(first5_char)
  return get_password_leaks_count(response, tail)
#it calls the get_password_leaks_count function to check if the password hash has been leaked and returns the count of leaks.


def main(args): #This function takes args as input, which represents a list of passwords.
  for password in args:
    count = pwned_api_check(password)
    if count:
      print(f'{password} was found {count} times... you should probably change your password!')
    else:
      print(f'{password} was NOT found. Carry on!')
  return 'done!'

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
#This block checks if the script is being run directly (__name__ == '__main__'). If so, it extracts the command-line arguments (passwords) using sys.argv[1:] and passes them to the main function.

