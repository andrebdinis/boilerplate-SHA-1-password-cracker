import hashlib
from pathlib import Path
from hmac import compare_digest

path = str(Path.cwd()) + "/"
#"/home/runner/boilerplate-SHA-1-password-cracker" + "/"
filename_salts = "known-salts.txt"
filename_passwords = "top-10000-passwords.txt"


def crack_sha1_hash(hash, use_salts=False):
  print('------------------------INPUT------------------------')
  print("HASH:", hash)
  print("USE_SALTS:", use_salts)
  with open(path+filename_passwords, 'r') as file_pw:
    for pw in file_pw:
      pw = removeNewLine(pw)
      if use_salts:
        with open(path+filename_salts, 'r') as file_salts:
          for salt in file_salts:
            salt = removeNewLine(salt)
            salted_pws = saltPassword(pw, salt)
            match = verifySaltedPasswords(pw, salted_pws, hash)
            if match:
              print("MATCH:", match)
              return match
      else:
        for pw in file_pw:
          pw = removeNewLine(pw)
          match = verifyPassword(pw, hash)
          if match:
            print("MATCH:", match)
            return match
  print("PASSWORD NOT IN DATABASE")
  return "PASSWORD NOT IN DATABASE"


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
      return password
  return False
