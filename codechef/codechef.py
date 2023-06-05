# # Update the '_' below to solve the problem

# #accept the count of test cases given in the the 1st line
# t = int(input()) 
# #run a loop to accept 't' inputs
# for i in range(t):     
#     #accept 2 integers on the 1st line of each test case
#     A, B = map(int,input().split())  
#     print(A)    
#     #accept 3 integers on the 2nd line of each test case
#     C, D, E = map(int,input().split())   
#     #output the 5 integers on a single line for each test case    
#     print(A, B, C, D, E)


# Update the '_' in the code below

#accept the count of test cases given in the the 1st line
# t = int(input())        
# #run a loop to accept 't' inputs
# for i in range(t):      
#     #accept 1 integer on the 1st line of each test case
#     N = int(input())        
#     #output the negative integer - i.e. (-N)
#     print(-N)


# Click on 'Next' once you are ready to proceed.
# t = int(input())
# for i in range(t):
#     A, C = map(int, input().split())
#     B = (A+C)/2
#     D = A+C
#     if int(B) and (D%2 == 0):
#         print(int(B))
#     else:
#         print(int(-1))


# Update the program below to solve the problem

# t = int(input())  # Number of test cases

# for _ in range(t):
#     X, Y, Z = map(int, input().split())  # Input the number of legs for chicken, duck, and total legs
    
#     # Check the conditions and print the appropriate result
#     if Z % 2 != 0 or Z < X or Z < Y or Z > (X * Y * 2) or Z < abs(X - Y):
#         print("NONE")
#     elif Z % X == 0 and Z % Y == 0:
#         print("ANY")
#     elif Z % X == 0 and Z%Y != 0:
#         print("CHICKEN")
#     elif Z % Y == 0 and Z%X != 0:
#         print("DUCK")


# t = int(input())
# for _ in range(t):
#     X = int(input())
#     if X%3 == 0:
#         print(X%3)
#     elif X%3 != 0:
#         Y = int(X%3)
#         if Y==1:
#             Z=(X-Y)+3
#             P = Z-X
#             print(P)            
#         elif Y==2:
#             Z=(X-Y)+3
#             P = Z-X
#             print(P)




# t = int(input())
# for _ in range(t):
#     X = int(input())
#     if X%3 == 0:
#         print(X%3)
#     elif (X+1)%3 == 0:
#         print(1)
#     elif (X+2)%3 == 0:
#         print(2)
#     else:
#         pass


# t = int(input())
# for _ in range(t):
#     X, Y = map(int, input().split())
#     Z = Y/2
#     normal_speed = X-Y
#     print(int(Z+normal_speed))


# t = int(input())
# for _ in range(t):
#     N, X = map(int, input().split())
#     if X == 0 or X == N:
#         print(0)
#     elif N>X:
#         if X>=5 and X<=N:
#             print(N-X)
#         else:
#             print(X)
#     elif X>N:
#         print(N)
#     else:
#         pass


# t = int(input())
# for i in range(t):
#     N, k = map(int, input().split())
#     A = list(map(int, input().split()))
    
#     #Declare and initialise variables - pos, neg and divk
#     #Note that we are reinitializing the variables to be 0 for each test case.
#     pos = 0
#     neg = 0
#     divk = 0
    
#     i = 0
#     #Loop through all elements of the array
#     while i<len(A):
#         #Count the negative elements of the array
#         if A[i] < 0:
#             neg = neg + 1
#         #Count the positive elements of the array
#         elif A[i] > 0:
#             pos = pos + 1
#         #Count if the given element is divisible by k
#         if A[i]%k == 0:
#             divk = divk + 1
#         i = i + 1
    
#     print(pos,neg,divk)

# t = int(input())
# for i in range(t):
#     A = list(map(int,input().split()))
    
#     #Calculate and store Team-1 and Team-2 scores
#     team1 = A[2] + A[4] + A[6] + A[8] + A[10]
#     team2 = A[1] + A[3] + A[5] + A[7] + A[9]
    
#     #Apply relevant conditions to check for victory
#     if team1 > team2:
#         print(1)
#     elif team1 < team2:
#         print(2)
#     else:
#         print(0)



# Update the '_' in the code below to solve the problem

# t = int(input())
# for i in range(t):
#     A = list(map(int,input().split()))
#     N = len(A)
    
#     # We first find the smallest element, and which index it is in.
#     minElement = A[0]
#     minElementIndex = 0
#     i = 1
#     while i < N:
#         if A[i] < minElement:
#             # If we find an element smaller than the previous smallest, we update
#             minElement = A[i]
#             minElementIndex = i
#         i = i + 1
    
#     #We are starting the operation from index of the smallest element
#     i = minElementIndex
#     while i > 0:
#         #Swap the A[i] and A[i-1]
#         A[i],A[i-1] = A[i-1], A[i]     
#         i = i - 1
    
#     print(*A)


# Update the '_' in the code below to solve the problem

# t = int(input())
# for i in range(t):
#     A = list(map(int, input().split()))
#     # length of the array A
#     n = len(A)      
#     # Initialise the right most index to 0
#     right = 0       
#     # Initilise the largest value to -100. The smallest element in A is -100
#     large = -100    
    
#     i = 0
#     while i<n:
#         # Here - we need to check if A[i] '=' large so that we can update the variable 'right'
#         if A[i] >= large:       
#             large = A[i]
#             right = i
#         i = i + 1
    
#     print(large, right)


# t = int(input())
# for i in range(t):
#     N = int(input())
#     A = list(map(int, input().split()))
#     # print(A)
#     # n = len(A)
#     # month = [m for m in range(1, 31)]
#     # print(month)
#     saturday = [6, 13, 20, 27]
#     sunday = [7, 14, 21, 28]
#     total = saturday+sunday+A
#     total1 = list(set(total))
#     print(len(total1))


# t = int(input())
# for i in range(t):
#     S = str(input())
#     reverse_string = ""
#     reverse_strings = ""
#     for i in S:
#         reverse_string =reverse_string+i
#         reverse_strings = i+reverse_strings
#     print(reverse_string)
#     print(reverse_strings)
  

# t = int(input())
# for i in range(t):
#     S = input()
#     T = input()
#     M = ""
    
#     for i in range(len(S)):
#         if S[i] == T[i]:
#             M=M+"G"
#         else:
#             M=M+"B"
#     print(M)



# Update the '_' in the code below to solve the problem

# t = int(input())
# for i in range(t):
#     A, B = map(int, input().split())
    
#     #Decare variables for lower and higher of the 2 numbers
#     minAB = min(A,B)        
#     maxAB = max(A,B)
#     flag = 0
    
#     while minAB <= maxAB:
#         print(minAB, maxAB)
#         #condition is met, hence set flag = 1
#         if minAB == maxAB:
#             print(minAB)
#             print(maxAB)  
#             flag = 1
#             break
#         else:
#             #update the minimum value as per the problem statement
#             minAB = minAB*2 
        
#     if flag == 1:
#         print('YES')
#     else:
#         print('NO')


# import math

# a = 24
# b = 32

# lcm = abs(a * b) // math.gcd(a, b)

# print(lcm)

# Update the code below to solve the problem

# t = int(input())
# for i in range(t):
#     N = int(input())
#     string = ""
#     for X in range(10):
#         for Y in range(10):
#             if N == (2*X+7*Y):
#                 print("YES")
#         break

            
# Update the code below to solve the problem

# t = int(input())
# for i in range(t):
#     N = int(input())
#     arr = []
#     for i in range(10):
#         mult = 2*i
#         mult1 = 7*i
#         arr.append(mult)
#         arr.append(mult1)
#     print(arr)
    
#     for i in range(len(arr)+1):
#         for ii in range(len(arr)+1):
#             sum = arr[i]+arr[ii]
#             arr.append(sum)
        
#     if N in set(arr):
#         print("YES")
#     else:
#         print("NO")
        
      
            
        
