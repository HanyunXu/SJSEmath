# Rabin cryptosystem  
# by HanyunXu  05/30/2015

from random import *
"""
    编程实现Rabin密码系统（参见P1363）：
1.  随机产生大素数p,q, p≡q≡3 mod 4 (位长28 bit) 及 p∙q=n
2.  对消息“m = Communication skill + Mathematical Fundation of Information Security + 201202001 + 学号 + 000001”进行数字化
3.  对明文消息m加密得到密文c
4.  对密文消息c解密得到明文

"""
# judge a prime or not	
def _try_composite(a, d, n, s):
    if pow(a, d, n) == 1:
        return False
    for i in range(s):
        if pow(a, 2**i * d, n) == n-1:
            return False
    return True # n  is definitely composite
 
def is_prime(n, _precision_for_huge_n=16):
    if n in _known_primes or n in (0, 1):
        return True
    if any((n % p) == 0 for p in _known_primes):
        return False
    d, s = n - 1, 0
    while not d % 2:
        d, s = d >> 1, s + 1
    if n < 1373653: 
        return not any(_try_composite(a, d, n, s) for a in (2, 3))
    if n < 25326001: 
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5))
    if n < 118670087467: 
        if n == 3215031751: 
            return False
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7))
    if n < 2152302898747: 
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11))
    if n < 3474749660383: 
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11, 13))
    if n < 341550071728321: 
        return not any(_try_composite(a, d, n, s) for a in (2, 3, 5, 7, 11, 13, 17))
    # otherwise
    return not any(_try_composite(a, d, n, s) 
                   for a in _known_primes[:_precision_for_huge_n])
 
_known_primes = [2, 3]
_known_primes += [x for x in range(5, 1000, 2) if is_prime(x)]

#generate p,q and n
# n:public key (p,q):private key
def generate():
    p = 4
    q = 4
    while not is_prime(p):
        p = 4 * randrange(2**25,2**26) + 3
    while not is_prime(q):
        q = 4 * randrange(2**25,2**26) + 3
    n = p * q
    print "\tPublic Key p = ", p, "\n\tPublic Key q = ",q ,"\n\tPrivate Key n = ", n, "\n"
    return p, q, n
    
def transfer(a):
    """
        transfer by character
        0-9: 0-9
        a-z: 10-35
        A-Z: 36-61
        "+": 62
        " ": 63
    """
    if ( 'a' <= a <= 'z' ):
        return ord(a) - 87         
    elif ( 'A' <= a <= 'Z' ):
        return ord(a) - 29
    elif ( a == '+' ):
        return 62
    elif ( a == ' ' ):
        return 63
    else:
        return a
# Communication skill + Mathematical Fundation of Information Security + 201202001 + 5130369055 + 000001

# DeTransfer
def de_transfer(c):
    if (0 <= c <= 9):
        return chr(c + 48)
    elif ( 10 <= c <= 35 ):
        return chr( c + 87 )         
    elif ( 36 <= c <= 61 ):
        return chr( c + 29 )
    elif ( c == 62 ):
        return '+'
    elif ( c == 63 ):
        return ' '
    else:
        return ' '

#digitalize
def digitalize(a):
    original_text = []
    plaintextM = 0
    flag = 0
    #letter to number stored in a list
    for i in range(len(a)):
        tt = transfer(a[i])
        original_text.append(tt)
    while len(original_text) != 0 :
        plaintextM += 64**flag * int(original_text.pop())
        flag += 1
  #  print "\nthe plaintext is ", plaintextM
    return plaintextM

def num_to_list(m):
    reverse = []
    sequence = []
    while m / 64 != 0 :
        reverse.append(m % 64)
        m = m / 64
     #   print m
    reverse.append(m)
    #print reverse
    while(reverse != []):
        for i in reverse:
            sequence.append(reverse.pop())
    return sequence

def anti_digitalize(c):
    text = ""
    for i in c:
        temp = str(de_transfer(i))
        text += temp
    return text

def encryption(m,n):
	c = mod_square(m, 2, n)
	#print "c = ",c
	return c

# Extended Euclidean algorithm
#给二整数 a 、b, 必存在有整数 x 、 y 使得ax + by = gcd(a,b)
def ext_euclid ( a , b ):
    if (b == 0):
        return 1 , 0 , a
    else:
        x , y , q=ext_euclid( b , a % b )
        x , y = y,( x - (a // b) * y )
        return x , y , q

# turn a number into binary
def dec_to_bin(num):
    m=[]               
    while num>=2:
        m.append(num%2)
        num=(num-num%2)/2
    m.append(num%2)
    return m

def mod_square(a,b,c):
    """a^b mod c=aa   return aa"""
    aa=1
    bb=a
    while(b!=0):
        if(b%2==1):
            aa=aa*bb%c;
        bb=bb*bb%c
        b=b/2
    return aa

def decryption(c,n,p,q):
    #print "start"
    s, t, gcd = ext_euclid(p, q)

    b1 = mod_square( c, (p + 1) / 4, p )
    b1 =  b1 % p
    b2 = mod_square( c, (q + 1) / 4, q )
    b2 =  b2 % q
   # print b1,b2;

    r1 = (s * p * b2 + t * q * b1) % n
    r2 = (s * p * b2 - t * q * b1) % n;
    r3 = (-s * p * b2 + t * q * b1) % n 
    r4 = (-s * p * b2 - t * q * b1) % n
    possible = [r1, r2, r3, r4]
  #  print possible;
    
    anti_dig = []
    
    for j in range(4):
   #     print possible[j]
        anti_dig.append(num_to_list(possible[j]))

    for i in range(4):
        temp = possible[i]
        if(temp%1000000==1):
         #   print "OK";
            break
    #print "decrpt_c = ",anti_dig[i]
    return temp/1000000;
        

def main():
    print "**************The Rabin cryptosystem***************"
    answer=""
    sno = raw_input ("请输入学号:") # input the students number
    mm = "Communication skill + Mathematical Fundation of Information Security + 201202001 + "+ sno +" + 000001"
    
    print "明文： ",mm
    print "\nThe Keys are generated randomly..."
    p, q, n = generate()
    print "密文："     
    for i in range(len(mm)):
        m = mm[i:i + 1];
        plaint_text = digitalize(m) * 1000000 + 1;
        c = encryption(plaint_text,n)
        print anti_digitalize(num_to_list(c)),
        tf = decryption(c,n,p,q)
        decrypt = num_to_list(tf);
        final = anti_digitalize(decrypt)
        #print "the decrypt text is ", final;
        answer += final
    print "\n\nAfter Decryption: \n", answer
main()


