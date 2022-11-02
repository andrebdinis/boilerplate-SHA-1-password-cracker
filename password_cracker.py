import hashlib
from pathlib import Path
from hmac import compare_digest
from collections import deque # more list-like efficient type

path = str(Path.cwd()) + "/"
#"/home/runner/boilerplate-SHA-1-password-cracker" + "/"
filename_salts = "known-salts.txt"
filename_passwords = "top-10000-passwords.txt"

# Function Efficiency Improvement:
# (BEFORE) v1: Iterating over files "with... as...". Ran 9 tests in 6.302s. OK.
# (BEFORE) v2: Iterating over lists. Ran 9 tests in 5.591s. OK.
# (ACTUAL) v3: Iterating over deques. Ran 9 tests in 4.229s. OK.
def crack_sha1_hash(hash, use_salts=False):
  print('------------- SHA-1 CRACKER TEST -------------')
  print('HASH:', hash)
  print('USE_SALTS:', use_salts)
  passwords = deque()
  with open(path+filename_passwords, 'r') as file_pw:
    for pw in file_pw:
      pw = removeNewLine(pw)
      passwords.append(pw)

  salts = deque()
  with open(path+filename_salts, 'r') as file_salts:
    for salt in file_salts:
      salt = removeNewLine(salt)
      salts.append(salt)

  if use_salts:
    for salt in salts:
      for pw in passwords:
        salted_pws = saltPassword(pw, salt)
        match = verifySaltedPasswords(pw, salted_pws, hash)
        if match:
          [matched_salted_pw, matched_pw] = match # destructuring array
          print('SALT:', salt)
          print('SALTED:', matched_salted_pw)
          print('PASSWORD:', matched_pw)
          return matched_pw
  else:
    for pw in passwords:
      match = verifyPassword(pw, hash)
      if match:
        print('PASSWORD:', match)
        return match

  msg = 'PASSWORD NOT IN DATABASE'
  print(msg)
  return msg


# BEFORE:
# v2: Iterating over lists. Ran 9 tests in 5.591s. OK.
def crack_sha1_hash_v2(hash, use_salts=False):
  print('------------------------INPUT------------------------')
  print("HASH:", hash)
  print("USE_SALTS:", use_salts)
  passwords = []
  with open(path+filename_passwords, 'r') as file_pw:
    for pw in file_pw:
      pw = removeNewLine(pw)
      passwords.append(pw)

  salts = []
  with open(path+filename_salts, 'r') as file_salts:
    for salt in file_salts:
      salt = removeNewLine(salt)
      salts.append(salt)

  if use_salts:
    for pw in passwords:
      for salt in salts:
        salted_pws = saltPassword(pw, salt)
        match = verifySaltedPasswords(pw, salted_pws, hash)
        if match:
          print("MATCH:", match)
          return match
  else:
    for pw in passwords:
      match = verifyPassword(pw, hash)
      if match:
        print("MATCH:", match)
        return match
  msg = 'PASSWORD NOT IN DATABASE'
  print(msg)
  return msg


# BEFORE:
# v1: Iterating over files "with... as...". Ran 9 tests in 6.302s. OK.
def crack_sha1_hash_v1(hash, use_salts=False):
  print('------------------------INPUT------------------------')
  print("HASH:", hash)
  print("USE_SALTS:", use_salts)      
  if use_salts:
    with open(path+filename_salts, 'r') as file_salts:
      for salt in file_salts:
        salt = removeNewLine(salt)
        with open(path+filename_passwords, 'r') as file_pw:
          for pw in file_pw:
            pw = removeNewLine(pw)
            salted_pws = saltPassword(pw, salt)
            match = verifySaltedPasswords(pw, salted_pws, hash)
            if match:
              print("MATCH:", match)
              return match
  else:
    with open(path+filename_passwords, 'r') as file_pw:
      for pw in file_pw:
        pw = removeNewLine(pw)
        match = verifyPassword(pw, hash)
        if match:
          print("MATCH:", match)
          return match
  print("PASSWORD NOT IN DATABASE")
  return "PASSWORD NOT IN DATABASE"

# ------------------------------------------------------------
# AUXILIARY FUNCTIONS

def removeNewLine(string):
  s = string[:]
  return s.replace('\n', '')

def generateHashSHA1(password):
  h = hashlib.sha1()
  h.update(bytes(password, 'utf-8'))
  return h.hexdigest()

def verifyPassword(password, hash):
  good_hash = generateHashSHA1(password)
  match = compare_digest(good_hash, hash)
  if match: return password
  return False

def saltPassword(password, salt):
  return [salt+password, password+salt]

def verifySaltedPasswords(password, salted_passwords, hash):
  for sp in salted_passwords:
    if verifyPassword(sp, hash):
      return [sp, password]
  return False