Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The proven prime
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
Acurve = 0; Bcurve = 7 # This defines the curve. y^2 = x^3 + Acurve * x + Bcurve
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424

#EC Functions, takes base 10 input only
def modinv(a,n=Pcurve): #Extended Euclidean Algorithm/'division' in elliptic curves
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        ratio = high/low
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECadd(xp,yp,xq,yq): # Not true addition, invented for EC. It adds Point-P with Point-Q.
    m = ((yq-yp) * modinv(xq-xp,Pcurve)) % Pcurve
    xr = (m*m-xp-xq) % Pcurve
    yr = (m*(xp-xr)-yp) % Pcurve
    return (xr,yr)

def ECdouble(xp,yp): # EC point doubling,  invented for EC. It doubles Point-P.
    LamNumer = 3*xp*xp+Acurve
    LamDenom = 2*yp
    Lam = (LamNumer * modinv(LamDenom,Pcurve)) % Pcurve
    xr = (Lam*Lam-2*xp) % Pcurve
    yr = (Lam*(xp-xr)-yp) % Pcurve
    return (xr,yr)

def EccMultiply(Scalar,xs=Gx,ys=Gy): # Double & add. EC Multiplication, Not true multiplication
    if Scalar == 0 or Scalar >= N: raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(Scalar))[2:]
    Qx,Qy=xs,ys
    for i in range (1, len(ScalarBin)): # This is invented EC multiplication.
        Qx,Qy=ECdouble(Qx,Qy); # print "DUB", Qx; print
        if ScalarBin[i] == "1":
            Qx,Qy=ECadd(Qx,Qy,xs,ys); # print "ADD", Qx; print
    return (Qx,Qy)

def pow_mod(x, y, z):
    #Calculates (x^y) % z
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number

def Compressed_to_full_point(x_point,parity):
    #X point as hex 64 bytes in length
    #Parity given as hex byte length 2 ie '02' or '03'
    #Returns tuple of x,y points as hex (padded)
    if not len(x_point) == 64 and len(parity) == 2: raise TypeError('Invalid input length')
    
    parity = int(parity,16) - 2 #Makes adjusting easier (-2 because can only be 02 or 03)
    x = int(x_point,16)
    
    #Calculated y squared    
    y_squared = (pow_mod(x, 3, Pcurve) + Bcurve) % Pcurve
    
    #Solves root of y squared
    #https://en.wikipedia.org/wiki/Quadratic_residue#Prime_or_prime_power_modulus
    y = pow_mod(y_squared, (Pcurve+1)//4, Pcurve)

    #Adjusts parity (negative point) % P
    if y % 2 != parity:
        y = -y % Pcurve

    #Converts to hex
    y_point = '%x' % y
    
    #Padding
    y_padded = "%s%s" % ('0'*(64-len(y_point)),y_point) 
    
    #Testing    
    assert len(y_padded) == 64
    return x_point,y_padded
