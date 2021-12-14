import math
import random
# Fonction exponentiation modulaire rapide

def modpow(m, exponent, n):
    """
    modpow(m,e,n)
    m = message to be encoded
    exponent = e_public key
    n = public_key
    Bignum modpow(Bignum base, Bignum exp, Bignum m) {
        Bignum result = 1;
        while (exp > 0) {
           if ((exp & 1) > 0) result = (result * base)b% m;
           exp >>= 1;
           base = (base * base)*% m;
        }
        return result;
    }
    """
    result = 1
    while exponent > 0:
        if (exponent & 1) > 0:  # 
            result = (result * m) % n
        exponent >>= 1  #bitwise shift to right
        m = (m * m)% n
    return result

def eucl(a, b):
    """
        Eucled Etendu
     Entrée : a, b entiers (naturels)
     Sortie : r entier (naturel) et  u, v entiers relatifs tels que r = pgcd(a, b) et r = a*u+b*v

     Initialisation : (r, u, v, r', u', v') := (a, 1, 0, b, 0, 1)
                       q  quotient entier

     les égalités r = a*u+b*v et r' = a*u'+b*v' sont des invariants de boucle

     tant que (r' ≠ 0) faire
         q := r÷r' 
         (r, u, v, r', u', v') := (r', u', v', r - q *r', u - q*u', v - q*v')
         fait
     renvoyer (r, u, v)
    """
    r, u, v, r_prim, u_prim, v_prim = a, 1, 0, b, 0, 1
    print(r, u, v, r_prim, u_prim, v_prim)
    r = (a*u) + (b*v)
    r_prim = (a*u_prim) + (b*v_prim)
    while r_prim != 0:
        quotient = int(r / r_prim)
        r, u, v, r_prim, u_prim, v_prim = r_prim, u_prim, v_prim, (r-(quotient * r_prim)), (u - (quotient*u_prim)), (v - (quotient* v_prim))

    return r, u, v

def isDivisble(i, n):
    """
        1: fonction EstPremier(n : entier >=  2 ) : bool een
        2: i <-- 2
        3: tant que i  <= sqrt(n) et i ne divise pas n:
            4: i <-- i + 1
        5: fin tant que
        6: retourner i > sqrt(n)
        7: fin fonction

        i divide n, if n = i * c  then  i | n
        5 | 20 because 20 = 5 * 4
        4 = 20 / 5
    """
    x = float(n / i)
    if x.is_integer():
        return True
    return False


def isPrime(n):
    """
    Si n est un entier compose, alors n admet un diviseur
    premier inferieur ou egal  a sqrt(n) .
    """
    if n < 2:
        return False
    else:
        i = 2
        while i <= math.sqrt(n) and not isDivisble(i, n):
            i += 1
    if i > math.sqrt(n):
        return True
    return False

# import random
# def decompose(n):
#     #on veut en sortie n-1=2^s.d avec d impair
#     r, s = 0, n - 1
#     while s % 2 == 0:
#         r += 1
#         s //= 2
#     return (s,r)

# def temoin(n,a):
#     (d,s)=decompose(n)
#     x=modpow(a,d,n)
#     if(x==1):
#         return False
#     if(x==n-1):
#         return False
#     for _ in range(s-1):
#         x=modpow(x,2,n)
#         if(x==n-1):
#             return False
#     return True

# def miller_rabin(n,k):
#     for _ in range(k):
#         a = random.randrange(2, n - 2)
#         if(temoin(n,a)):
#             return False
#     return True

def generate_random_prime(max):
    while(True):
        p=random.randrange(5, max)
        if isPrime(p):
            break
    return p

def randomize_pq(max):
    p=generate_random_prime(max)
    while(True):
        q=generate_random_prime(max)
        if(p!=q):
            break
    return(p,q)

def enc(m,e,n):
    return modpow(m,e,n)

def dec(c,d,n):
    return modpow(c,d,n)

def gen_keys(p,q):
    n = p*q
    phi = (p-1)*(q-1)
    while(True):
        e=random.randrange(1, phi-1)
        (pgcd,d,v)=eucl(e,phi)
        if(pgcd==1):
            break
    if(d<0):
        d=d%phi
    return (e,d,n)
    
def rsa_custom(max):
    """
    ### Génération des clés
    # Implémetez maintenant l'algorithme de génération des clés de RSA :
    # 1. Générez aléatoirement 2 grands nombres premiers, *p* et *q*
    # 1-1 calculez *n = p.q*
    # 1-2 calculez phi = (p-1).(q-1)
    # 2. Générez aléatoirement un nombre *e* tel que *PGCD(e, phi)=1*
    #    Le couple *(e,n)* est la clé publique
    # 3. Calculez *d* l'inverse de *e mod phi*
    #    *d* est la clé privée
    """
    p, q = randomize_pq(max)  # <-- 1
    n = p * q # <-- 1-1
    phi = (p-1)*(q-1) # <-- 1-2
    e_pub,d_pri,n_pub = gen_keys(p,q) # <-- 2 et 3 
    return e_pub,d_pri,n_pub


# e_pub, d_pri, n_pub = rsa_custom(100)
# chifre = enc(10, e_pub, n_pub)
# decoded = dec(chifre, d_pri, n_pub)

# print('e_pub = {} ,d_pri = {} ,n_pub = {}'.format(e_pub,d_pri,n_pub))
# print('Encoded 10 is ',chifre)
# print('decoded :', decoded)


# ### Validation
# Vérifiez la validité de votre implémentation avec quelques tests simples du type :
# `m=random`
# `if(m != DEC(ENC(m,(e,n)),(d,n))) then ERROR`

def validate(min, max): 
    message = random.randrange(min, max)
    e_pub, d_pri, n_pub = rsa_custom(max)
    encoded = enc(message, e_pub, n_pub)
    decoded = dec(encoded, d_pri, n_pub)
    if message != decoded:
        return message, encoded, decoded, e_pub, d_pri, n_pub, False
    return message, encoded, decoded, e_pub, d_pri, n_pub, True

def test_validation(min, max):
    status = True
    compt = 1
    with open('decoding_encoding_result.txt', 'w') as f:
        while status:
            message, encoded, decoded, e_pub, d_pri, n_pub, status = validate(min, max)
            f.write('*************************Test  number {}**************\n'.format(compt))
            f.write('Encoded of message {} is {}\n'.format(message, encoded))
            f.write('Decoded of message {} is {}\n'.format(message, decoded))
            f.write('Public keys are : {} and {}\n'.format(e_pub, n_pub))
            f.write('Private key used for decoding is {}\n'.format(d_pri))
            f.write('Status of encoding and decoding is {}\n'.format(status))
            f.write('*******************************************************\n')
            compt+=1
        f.write('**** Error ******\n')
        f.write('Encoded of message {} is {}\n'.format(message, encoded))
        f.write('Decoded of message {} is {}\n'.format(message, decoded))
        f.write('Public keys are : {} and {}\n'.format(e_pub, n_pub))
        f.write('Private key used for decoding is {}\n'.format(d_pri))
        f.write('Status of encoding and decoding is {}\n'.format(status))


#test_validation(5, 2000)


# def enc(m,e,n):
#     return modpow(m,e,n)

# def dec(c,d,n):
#     return modpow(c,d,n)

x = enc(10, 5, 85)
print('Example class chiffré = ', x)


m = dec(x, 13 , 85)
print('Example class message = ',m)




x = enc(240, 23, 323)
print('chiffre 1= ', x)


m = dec(179, 263 , 323)
print('message 1 = ',m)



# key = gen_keys(5, 19)  
# print('key = ',key)  # e, d, n

x = enc(240, 23, 323)
print('chiffre 2 = ', x)

m = dec(86, 67 , 95)
print('message 2 = ',m)


        
