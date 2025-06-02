# for the birthday problem, test which function is the most accurate and improve function(s) if possible
# to test accuracy, I'm only checking how close it is to the answer using gamma functions for factorials (f_exact function). It's important to note that ramanujan approximation is more accurate then gamma functions so function g is the most accurate solution.

import math
from decimal import Decimal, getcontext
from concurrent.futures import ProcessPoolExecutor, as_completed
import matplotlib.pyplot as plt
import os
from mpmath import mp, gamma

mp.dps = 200  # set desired decimal places of precision

getcontext().prec = 200 # 200 decimal points supported in Decimal

# calculate number of threads each function (f,g,a) should use. More than 14 threads prefferable
count = os.cpu_count() - 2 # leave 2 threads empty so nothing crashes
if count >= 5: # if you have 7 or more threads
    count-=1  # a only needs 1 thread
    # count_f = math.ceil(count/2) + 1 # needs most threads
    # count_g = math.floor(count/2) - 1 # needs less then f but still a lot
    count_fg = count
else:
    # give 1 thread each if no more supported
    # still requires at least 3 threads, but this should never be necessary on any modern computer.
    # a function uses 1 thread as well, so does f & g
    # count_f = 1
    # count_g = 1
    count_fg = 2

threads = [None]*(count_fg) # initialize count_fg threads

# set rules for all functions
gather = 100 # gather this many points of data to graph
increment_b = 1000000000 # increment b by ... timeseach time

# gathered points from a function
# gathered_a_x = [None]*gather # gathered a is set in gather_a function
# gathered_a_y = [None]*gather
gathered_g_x = [None]*gather
gathered_g_y = [None]*gather

# accuracies
accuracies_f_a = [None]*gather
accuracies_f_g = [None]*gather

e = Decimal(1e-200) # accuracy for the secant method
N = 100000 # max iteration count for secant method

def log(x, base=Decimal(math.e)):
    if base==Decimal(math.e):
        return x.ln()
    return Decimal(x).ln()/base.ln()

# my approximation equation
def g(b, k):
    c = Decimal(b*log(b) + log(1/Decimal(math.pi)**3 + b*(1+4*b*(1+2*b)) )/6) - log(Decimal(0.5))
    x = b-k
    return c - (x*log(x) + k  + log(b)*k + log(1/Decimal(math.pi)**3 + x*(1+4*x*(1+2*x)))/6)

# birthday problem original equation but only for integers
def f(b, k):
    #return Decimal(math.factorial(b))/Decimal(math.factorial(b-k))/b**k # return percentage result

    # more efficient implementation of the birthday problem
    delta = b-k+1
    fact = delta
    multiplier = delta+1 # start with delta, increment to b
    for i in range(delta+1, b+1):
        fact*=multiplier
        multiplier+=1
    return Decimal(fact)/b**k

# exact equation for non-int inputs
def f_exact(b, k):
    # use gamma function from mpmath library for non-int factorials
    return gamma(b+1)/gamma(b-k+1)/b**k - 0.5

# approximation equation
def a(b): # returns k
    return Decimal(0.5) + Decimal(Decimal(1/4) + 2*Decimal(2).ln()*b).sqrt()

def secant(fun, b, x0,x1,e,N):
    step = 1
    condition = True
    x2 = 0.0
    while condition:
        if fun(b, x0) == fun(b, x1): 
            print('division of zero')
            break
        x2 = (x0 - (x1-x0)*fun(b, x0)/( fun(b, x1) - fun(b, x0) ))
        #print(f'Iteration {step}, x2 = {x2} and fun(x2) = {fun(x2)}')
        x0 = x1
        x1 = x2
        step = step + 1
        if step > N:
            print('Not Convergent!')
            break
        condition = abs(fun(b, x2)) > e
    print(f'\n root: {x2}')
    return x2

# gather data with g(b,k)
def iter_g(b, i):
    x0 = Decimal(a(b)) # approx
    x1 = Decimal(math.sqrt(b)) # approx
    k = secant(g, b, x0, x1, e, N) # get k
    
    #gathered_g_x[i] = b
    #gathered_g_y[i] = k
    return i, b, k # need to return since multi-threading using a pool
    # b+=increment_b

#b = Decimal(365)
#x0 = Decimal(a(b)) # approx
#x1 = Decimal(math.sqrt(b)) # approx
#print("g(b, k):", end='')
#k = secant(g, b, x0, x1, e, N)#+(Decimal(2).ln()/3) # get k
#
## find exact birthday problem solution
#k_fg = f_exact(float(b), float(k))
#print("\nf(b, k):", end='')
#k_f = secant(f_exact, mp.mpf(str(b)), mp.mpf(str(x0)), mp.mpf(str(x1)), mp.mpf(str(e)), N)#+(Decimal(2).ln()/3) # get k
#print("accuracy from 0.5: ", k_fg)
#print("exact solution:    ", k_f)
#print("g(b,k) off by:     ", k_f-mp.mpf(str(k)))
#
#exit(0)

# pass a,g function's values through f to see how close it is to 0.50, closer they are, higher the accuracy
def gather_accuracy(g_called, gathered_x, gathered_y, i): # input k list
    return f_exact(mp.mpf(str(gathered_x[i])), mp.mpf(str(gathered_y[i]))), g_called, i # g_called is only to show if its the g function

# gather data with a(b)
# faster function so it's only a single task
def gather_a(b): # b contains initial value of b
    gather_a_x = [None]*gather
    gather_a_y = [None]*gather
    for i in range(gather):
        k = a(b)
        gather_a_x[i] = b
        gather_a_y[i] = k
        b+=increment_b
        #gather_accuracy(accuracies_f_a, gathered_a_x, gathered_a_y, i) # gather accuracy after calculating
    return gather_a_x, gather_a_y

# gather data with g,a using a multi threading queue
def gather_ga():
    b = Decimal(increment_b)# Decimal(365 if 365 < increment_b else increment_b) # initial b, make sure graph is always in increasing order for readability
        
    # As threads join, start gathering accuracies
    with ProcessPoolExecutor(max_workers=count_fg) as executor:
        # set tasks: iter_g, gather_a, gather_accuracy
        tasks = []
        tasks.append(executor.submit(gather_a, b))
        for i in range(gather):
            tasks.append( executor.submit(iter_g, b, i) )
            # tasks.append( (gather_accuracy, gathered_g_x, gathered_g_y) ) # add accuracy, should do so only after previous task is finished, also calculate accuracy for a
            b += increment_b

        for task in as_completed(tasks):
            try:
                i, b_g, k_g = task.result()

                gathered_g_x[i] = b_g
                gathered_g_y[i] = k_g
            except ValueError:
                gathered_a_x, gathered_a_y = task.result()
    return gathered_a_x, gathered_a_y

                # don't get result if error since gather_a is causing it

# determines which is closer to 50%
def g_is_more_accurate():
    g_to_0_counter = 0 # number of times g is closer to 0
    a_to_0_counter = 0
    for i in range(gather):
        # calculate differences, and check which is closer to 0
        delta_a = abs(accuracies_f_a[i]-Decimal(0.50))
        delta_g = abs(accuracies_f_g[i]-Decimal(0.50))
        if delta_a < delta_g:
            # a is closer to zero
            a_to_0_counter+=1
        elif delta_a == delta_g:
            # g & a is closer to zero
            a_to_0_counter+=1
            g_to_0_counter+=1
        else:
            g_to_0_counter+=1

    if g_to_0_counter > a_to_0_counter:
        return True, g_to_0_counter, a_to_0_counter # g is more accurate
    else:
        return False, g_to_0_counter, a_to_0_counter # a is more accurate
    # g accuracy in percentage: g_to_0_counter/gather*100

# gather accuracies of functions g,a using function f_exact (function g is the most accurate
# but using an isolated solution to compare functions g,a is good enough)
def gather_ga_accuracies_f(gathered_a_x, gathered_a_y):
    getcontext().prec = 3000 # set decimal digit count to 3000
    mp.dps = 3000            # set decimal digit count to 3000

    with ProcessPoolExecutor(max_workers=count_fg) as executor:
        # set tasks: iter_g, gather_a, gather_accuracy
        tasks = []
        for i in range(gather):
            # calculate accuracy, should do so only after previous task is finished

            # filter out the k values (y) if they are equal as an int. E.g. gathered__x/y is the same for both a,g
            if(int(gathered_a_y[i]) == int(gathered_g_y[i])):
                # assign them an arbitrary number that's equal for both. No need to calculate it as the result would've been the same
                accuracies_f_a[i] = Decimal(0.50)
                accuracies_f_g[i] = Decimal(0.50) # it's impossible for the number to be exactly 0.50, so if accuracies_f[i] = 0.50, it means they resulted in the same value.
            else:
                tasks.append( executor.submit(gather_accuracy, 1, gathered_g_x, gathered_g_y, i) ) # 1 for g function
                tasks.append( executor.submit(gather_accuracy, 0, gathered_a_x, gathered_a_y, i) ) # 0 for a function

        for task in as_completed(tasks):
            accuracy, g_called, i = task.result()
            if g_called: # if function g is called
                accuracies_f_g[i] = accuracy
            else:
                accuracies_f_a[i] = accuracy

# graph the differences between a(b) and g(b, k)
def graph_delta_gaf_functions(sub, gathered_a_y):
    # calculate delta
    delta = [None]*gather
    for i in range(gather):
        delta[i] = abs(gathered_g_y[i]-Decimal(gathered_a_y[i]))

    # test print values
    print(delta) # wierd discovery that function g requires +ln(2)/3 added to resulting k
    print()
    print(gathered_g_y)
    print()
    print(gathered_a_y)
    print()

    # graph
    sub.plot(gathered_g_x, delta, label='Δ = | k_g(b, k)-a(b) |', marker='.', markersize=5, linestyle='-', linewidth=3, color='green')
    sub.set_xlabel('Total Number of Combinations (b)')
    sub.set_ylabel('Differences in k for g,a Functions')
    sub.set_title('Differences in k for g,a vs. Total Number of Combinations (b)')
    sub.legend()
    sub.grid(True)

def graph_gaf_functions(sub, gathered_a_x, gathered_a_y):
    # graph
    sub.plot(gathered_g_x, gathered_g_y, label='g(b, k)', marker='.', markersize=3, linestyle='-', linewidth=2, color='blue')
    sub.plot(gathered_a_x, gathered_a_y, label='a(b)', marker='s', markersize=3, linestyle='dotted', color='red')
    sub.set_xlabel('Total Number of Combinations (b)')
    sub.set_ylabel('Count Needed for a 50% Chance of Collision (k)')
    sub.set_title('Side by Side Comparision')
    sub.legend()
    sub.grid(True)

# start gathering data for g,a multi-threading
gathered_a_x, gathered_a_y =  gather_ga()

# now graph them
_, (sub1, sub2) = plt.subplots(1, 2, figsize=(13, 4))  # width x height in inches

graph_gaf_functions(sub1, gathered_a_x, gathered_a_y)
graph_delta_gaf_functions(sub2, gathered_a_y)

plt.title("Birthday Problem Approximation Equations Comparision")
plt.savefig("../sec.pdf", format="pdf")
plt.show()

# gather accuracies and check which ones are closer to 50%
gather_ga_accuracies_f(gathered_a_x, gathered_a_y)

getcontext().prec = 200 # set back to 200 digits for faster calculations in g_is_more_accurate function

g_is_accurate, g_to_0_counter, a_to_0_counter = g_is_more_accurate()
print(f"g is more accurate: {g_is_accurate} \ng is closer/equal to zero than a: {g_to_0_counter}\na is closer/equal to zero than g: {a_to_0_counter}")

# Tests show that function g is the most accurate solution (more accurate then function a), but  a(b) - ln(2)/3
# is really close to g(b,k)->k. They are essentially the same. Considering that you want a solution for integers.
# This means that function a is faster and more convinient to use (no secant method needed). The ln(2)/3 comes
# from the derivation of the a(b) function. I know that a(b) isn't more accurate is due to the fact that 
# ramanujan approximation is the most accurate solution and both results passed through gamma function solution
# defined in f_exact function and function g gives a resulting collision chances closer to 0.50 than function a.
# The small flaw with this is that since function g is the most accurate solution, even f_exact function isn't
# going to show the exact accuracy. So the accuracy can only be determined accurately relative to a obviously
# less accurate function like function a.
