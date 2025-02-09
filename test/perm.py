a = [i for i in range(32)]
b = a[:]
p = a[:]

# derivation of the n_V matrix
for k in range(4):
    for i in range(32//4):
        p[i] = b[i*4]
        p[i+8] = b[i*4+1]
        p[i+16] = b[i*4+2]
        p[i+24] = b[i*4+3]
    b = p[:]
    print(p)
    copy = p[:]
    for m in range(3):
        for i in range(32//4):
            for n in range(4):
                p[i*4+n]  = copy[(1+n+m)%4+i*4]
        print(p)
    b = p[:]

