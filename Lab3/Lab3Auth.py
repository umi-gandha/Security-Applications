import pyotp

base32secret3232 = 'JBSWY3DPEBLW64TMMFQW45DP'
totp = pyotp.TOTP(base32secret3232)
print(totp.now())