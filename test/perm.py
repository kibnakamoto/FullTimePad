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

print("LITTLE ENDIAN: ")
# a is the result when the big endian permutation matrix is applied to vector with values 0-31
a = [
[0, 4, 8, 12, 16, 20, 24, 28, 1, 5, 9, 13, 17, 21, 25, 29, 2, 6, 10, 14, 18, 22, 26, 30, 3, 7, 11, 15, 19, 23, 27, 31],
[16, 1, 17, 0, 18, 3, 19, 2, 20, 5, 21, 4, 22, 7, 23, 6, 24, 9, 25, 8, 26, 11, 27, 10, 28, 13, 29, 12, 30, 15, 31, 14],
[20, 22, 16, 18, 28, 30, 24, 26, 5, 7, 1, 3, 13, 15, 9, 11, 21, 23, 17, 19, 29, 31, 25, 27, 4, 6, 0, 2, 12, 14, 8, 10],
[13, 20, 28, 5, 12, 21, 29, 4, 15, 22, 30, 7, 14, 23, 31, 6, 9, 16, 24, 1, 8, 17, 25, 0, 11, 18, 26, 3, 10, 19, 27, 2],
[14, 10, 23, 19, 31, 27, 6, 2, 13, 9, 20, 16, 28, 24, 5, 1, 12, 8, 21, 17, 29, 25, 4, 0, 15, 11, 22, 18, 30, 26, 7, 3],
[30, 24, 26, 28, 7, 1, 3, 5, 12, 10, 8, 14, 21, 19, 17, 23, 29, 27, 25, 31, 4, 2, 0, 6, 15, 9, 11, 13, 22, 16, 18, 20],
[19, 16, 21, 22, 23, 20, 17, 18, 24, 27, 30, 29, 28, 31, 26, 25, 1, 2, 7, 4, 5, 6, 3, 0, 10, 9, 12, 15, 14, 13, 8, 11],
[13, 28, 14, 31, 11, 26, 8, 25, 2, 19, 1, 16, 4, 21, 7, 22, 6, 23, 5, 20, 0, 17, 3, 18, 9, 24, 10, 27, 15, 30, 12, 29],
[30, 29, 23, 20, 17, 18, 24, 27, 4, 7, 13, 14, 11, 8, 2, 1, 15, 12, 6, 5, 0, 3, 9, 10, 21, 22, 28, 31, 26, 25, 19, 16],
[16, 12, 5, 25, 10, 22, 31, 3, 2, 30, 23, 11, 24, 4, 13, 17, 19, 15, 6, 26, 9, 21, 28, 0, 1, 29, 20, 8, 27, 7, 14, 18],
[15, 26, 7, 18, 29, 8, 21, 0, 16, 5, 24, 13, 2, 23, 10, 31, 19, 6, 27, 14, 1, 20, 9, 28, 12, 25, 4, 17, 30, 11, 22, 3],
[14, 11, 3, 6, 17, 20, 28, 25, 7, 2, 10, 15, 24, 29, 21, 16, 27, 30, 22, 19, 4, 1, 9, 12, 18, 23, 31, 26, 13, 8, 0, 5],
[19, 26, 3, 10, 22, 31, 6, 15, 8, 1, 24, 17, 13, 4, 29, 20, 5, 12, 21, 28, 0, 9, 16, 25, 30, 23, 14, 7, 27, 18, 11, 2],
[7, 3, 24, 28, 14, 10, 17, 21, 9, 13, 22, 18, 0, 4, 31, 27, 25, 29, 6, 2, 16, 20, 15, 11, 23, 19, 8, 12, 30, 26, 1, 5],
[24, 22, 2, 12, 28, 18, 6, 8, 0, 14, 26, 20, 4, 10, 30, 16, 31, 17, 5, 11, 27, 21, 1, 15, 7, 9, 29, 19, 3, 13, 25, 23],
[26, 11, 19, 2, 20, 5, 29, 12, 28, 13, 21, 4, 18, 3, 27, 10, 6, 23, 15, 30, 8, 25, 1, 16, 0, 17, 9, 24, 14, 31, 7, 22],
]

# convert results to little endian (reverse order of bytes in 32-bit segment)
for i in range(16):
    perm = []
    for j in range(0, 32, 4):
        # Slice the 4 bytes and reverse their order (little-endian conversion)
        perm.extend(a[i][j:j+4][::-1])
    a[i] = perm[:]

# Get values of vector before permutation applied
# Mi,j = Vi-1.index(Vi,j) where M is permutation matrix and Vi is the vector a[i]
# Find Mi,j

for i in range(16):
    # Initialize the permutation vector
    p = []

    if i==0: # first indexing
        prev = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28]
    else:
        prev = a[i-1]

    # Iterate over the result array and find the corresponding index in the input array
    for j in range(32):
        # Find the index of elem in the input array
        p.append(prev.index(a[i][j]))
    print(p)

