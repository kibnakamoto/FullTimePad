a = [i for i in range(32)]
b = a[:] 
p = a[:]
V = [] # resulting matrix

# derivation of the n_V matrix for big endian
print("BIG ENDIAN: ")
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

b = a[:] 
p = a[:]
V_lit = [] # resulting matrix

print("LITTLE ENDIAN: ")
# derivation of the n_V matrix for little endian
for k in range(4):
    for i in range(32//4):
        p[i] = b[i*4]
        p[i+8] = b[i*4+1]
        p[i+16] = b[i*4+2]
        p[i+24] = b[i*4+3]
    b = p[:]

    # to make it big endian, every 4 bytes should be reversed without modyfing the original data. so that no matter the endiannes, the hash is the same
    toprint = p[:]
    for i in range(32//4):
        # switch 3 and 0
        temp = toprint[i*4]
        toprint[i*4] = toprint[i*4+3]
        toprint[i*4+3] = temp

        # switch 2 and 1
        temp = toprint[i*4+1]
        toprint[i*4+1] = toprint[i*4+2]
        toprint[i*4+2] = temp
    print(toprint)

    V_lit.append(p[:])
    copy = p[:]
    for m in range(3):
        for i in range(32//4):
            for n in range(4):
                p[i*4+n]  = copy[(1+n+m)%4+i*4]

        # to make it big endian, every 4 bytes should be reversed without modyfing the original data. so that no matter the endiannes, the hash is the same
        toprint = p[:]
        for i in range(32//4):
            # switch 3 and 0
            temp = toprint[i*4]
            toprint[i*4] = toprint[i*4+3]
            toprint[i*4+3] = temp

            # switch 2 and 1
            temp = toprint[i*4+1]
            toprint[i*4+1] = toprint[i*4+2]
            toprint[i*4+2] = temp
        print(toprint)

        V_lit.append(p[:])
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
