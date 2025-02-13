import math
import numpy as np
from decimal import Decimal, getcontext

getcontext().prec = 200

b = Decimal(0xfffffffb**8)
# b = Decimal(365)

def log(x, base=Decimal(math.e)):
    if base==Decimal(math.e):
        return x.ln()
    return Decimal(x).ln()/base.ln()

c = Decimal(b*log(b) + log( b*(1+4*b*(1+2*b)) )/6 - log(b) * log(0.5, b))

def f(k):
    k = Decimal(k)
    x = b-k
    return c - (x*log(x) + k  + log(b)*k + log(x*(1+4*x*(1+2*x)))/6)

def secant(x0,x1,e,N):
    print('\n\n*** SECANT METHOD IMPLEMENTATION ***')
    step = 1
    condition = True
    x2 = 0.0
    while condition:
        if f(x0) == f(x1): 
            print('Divide by zero error!')
            break

        x2 = (x0 - (x1-x0)*f(x0)/( f(x1) - f(x0) ))
        print(f'Iteration-{step}, x2 = {x2} and f(x2) = {f(x2)}')
        x0 = x1
        x1 = x2
        step = step + 1

        if step > N:
            print('Not Convergent!')
            break

        condition = abs(f(x2)) > e

    print(f'\n Required root is: {x2}')
    return x2

x0 = Decimal(2**172)
x1 = Decimal(1496577676626844588240573268701473812127674924007424)
e = Decimal(1e-500)

N = 100000
x2 = secant(x0, x1, e, N)
print(f(x2), x2)
