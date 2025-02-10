a = [i for i in range(32)]
b = a[:] 
p = a[:]
V = [] # resulting matrix

# derivation of the n_V matrix
for k in range(4):
    for i in range(32//4):
        p[i] = b[i*4]
        p[i+8] = b[i*4+1]
        p[i+16] = b[i*4+2]
        p[i+24] = b[i*4+3]
    b = p[:]
    print(p)
    V.append(p[:])
    copy = p[:]
    for m in range(3):
        for i in range(32//4):
            for n in range(4):
                p[i*4+n]  = copy[(1+n+m)%4+i*4]
        print(p)
        V.append(p[:])
    b = p[:]

# print the matrix to represent in latex document
#for i in range(16):
#    for j in range(32):
#        if V[i][j] < 9:
#            phantom = "\phantom{0}"
#        else:
#            phantom = ""
#            
#        if j < 31:
#
#            print(phantom + str(V[i][j]), end=' & ')
#        else: 
#            print(phantom + str(V[i][j]), end=' \\\\')
#    print() 
