#! /usr/bin/python
# -*- coding: UTF-8 -*-
# formatted for tab-stops 4
#
#	By Peter Schorn, peter.schorn@acm.org, December 2004 - November 2005
#
# Decompose a non-negative integer into the sum of at most four squares.
# Last change 25-Nov-2005, simplified decomposeProbablePrime
# Last change 13-Nov-2005, optimized search loop
# Last change 30-Oct-2005, improved isqrt function
# Last change  8-May-2005, improved isqrt function

import sys, operator, math, random

# Return the greatest common divisor using Euclid's algorithm
def	gcd(a, b):
	while b:
		a, b = b, a % b
	return a

# 'l' is a list of tuples where the first elements form the argument to 'func'
# and the last element is the expected result. Returns True iff all tests
# succeed.
def	testfunc(func, l):
	return False not in [func(*x[:-1]) == x[-1] for x in l]

# Test the gcd function
# Returns True if no error has been detected
def	testgcd():
	return testfunc(gcd, [(4, 6, 2), (6, 4, 2),
		(1, 1, 1), (2, 1, 1), (1, 2, 1), (13000, 17000, 1000), (3, 4, 1)])

# Compute the jacobi symbol (a / b)
#	Precondition: b odd
#	Postcondition: Result is jacobi symbol (a / b) or 0 iff gcd(a, b) != 1
def	jacobi(a, b):
	s = 1
	while a > 1:
		d4 = a >> 2
		m4 = a & 3
		if	m4:					# a % 4 != 0
			if	m4 == 2:		# a % 4 = 2 (i.e. a % 2 = 0)
				if	b & 7 in [3, 5]:
					s = -s
				a >>= 1
			else:
				if	m4 == b & 3 == 3:
					s = -s
				a, b = b % a, a
		else:					# a % 4 = 0
			a = d4				# a = a / 4
	return a and s

# Test the jacobi function by comparing with a pre-computed table
# Returns True if no error has been detected
def	testjacobi():
	return testfunc(jacobi, [
		(1, 1, 1), (1, 3, 1), (1, 5, 1), (1, 7, 1), (1, 9, 1), (1, 11, 1),
		(1, 13, 1), (1, 15, 1), (1, 17, 1), (1, 19, 1), (1, 21, 1), (1, 23,
		1), (1, 25, 1), (1, 27, 1), (1, 29, 1), (1, 31, 1), (2, 1, 1), (2, 3,
		-1), (2, 5, -1), (2, 7, 1), (2, 9, 1), (2, 11, -1), (2, 13, -1), (2,
		15, 1), (2, 17, 1), (2, 19, -1), (2, 21, -1), (2, 23, 1), (2, 25, 1),
		(2, 27, -1), (2, 29, -1), (2, 31, 1), (3, 1, 1), (3, 3, 0), (3, 5,
		-1), (3, 7, -1), (3, 9, 0), (3, 11, 1), (3, 13, 1), (3, 15, 0), (3,
		17, -1), (3, 19, -1), (3, 21, 0), (3, 23, 1), (3, 25, 1), (3, 27, 0),
		(3, 29, -1), (3, 31, -1), (4, 1, 1), (4, 3, 1), (4, 5, 1), (4, 7, 1),
		(4, 9, 1), (4, 11, 1), (4, 13, 1), (4, 15, 1), (4, 17, 1), (4, 19, 1),
		(4, 21, 1), (4, 23, 1), (4, 25, 1), (4, 27, 1), (4, 29, 1), (4, 31,
		1), (5, 1, 1), (5, 3, -1), (5, 5, 0), (5, 7, -1), (5, 9, 1), (5, 11,
		1), (5, 13, -1), (5, 15, 0), (5, 17, -1), (5, 19, 1), (5, 21, 1), (5,
		23, -1), (5, 25, 0), (5, 27, -1), (5, 29, 1), (5, 31, 1), (6, 1, 1),
		(6, 3, 0), (6, 5, 1), (6, 7, -1), (6, 9, 0), (6, 11, -1), (6, 13, -1),
		(6, 15, 0), (6, 17, -1), (6, 19, 1), (6, 21, 0), (6, 23, 1), (6, 25,
		1), (6, 27, 0), (6, 29, 1), (6, 31, -1), (7, 1, 1), (7, 3, 1), (7, 5,
		-1), (7, 7, 0), (7, 9, 1), (7, 11, -1), (7, 13, -1), (7, 15, -1), (7,
		17, -1), (7, 19, 1), (7, 21, 0), (7, 23, -1), (7, 25, 1), (7, 27, 1),
		(7, 29, 1), (7, 31, 1), (8, 1, 1), (8, 3, -1), (8, 5, -1), (8, 7, 1),
		(8, 9, 1), (8, 11, -1), (8, 13, -1), (8, 15, 1), (8, 17, 1), (8, 19,
		-1), (8, 21, -1), (8, 23, 1), (8, 25, 1), (8, 27, -1), (8, 29, -1),
		(8, 31, 1), (9, 1, 1), (9, 3, 0), (9, 5, 1), (9, 7, 1), (9, 9, 0), (9,
		11, 1), (9, 13, 1), (9, 15, 0), (9, 17, 1), (9, 19, 1), (9, 21, 0),
		(9, 23, 1), (9, 25, 1), (9, 27, 0), (9, 29, 1), (9, 31, 1), (10, 1,
		1), (10, 3, 1), (10, 5, 0), (10, 7, -1), (10, 9, 1), (10, 11, -1),
		(10, 13, 1), (10, 15, 0), (10, 17, -1), (10, 19, -1), (10, 21, -1),
		(10, 23, -1), (10, 25, 0), (10, 27, 1), (10, 29, -1), (10, 31, 1),
		(11, 1, 1), (11, 3, -1), (11, 5, 1), (11, 7, 1), (11, 9, 1), (11, 11,
		0), (11, 13, -1), (11, 15, -1), (11, 17, -1), (11, 19, 1), (11, 21,
		-1), (11, 23, -1), (11, 25, 1), (11, 27, -1), (11, 29, -1), (11, 31,
		-1), (12, 1, 1), (12, 3, 0), (12, 5, -1), (12, 7, -1), (12, 9, 0),
		(12, 11, 1), (12, 13, 1), (12, 15, 0), (12, 17, -1), (12, 19, -1),
		(12, 21, 0), (12, 23, 1), (12, 25, 1), (12, 27, 0), (12, 29, -1), (12,
		31, -1), (13, 1, 1), (13, 3, 1), (13, 5, -1), (13, 7, -1), (13, 9, 1),
		(13, 11, -1), (13, 13, 0), (13, 15, -1), (13, 17, 1), (13, 19, -1),
		(13, 21, -1), (13, 23, 1), (13, 25, 1), (13, 27, 1), (13, 29, 1), (13,
		31, -1), (14, 1, 1), (14, 3, -1), (14, 5, 1), (14, 7, 0), (14, 9, 1),
		(14, 11, 1), (14, 13, 1), (14, 15, -1), (14, 17, -1), (14, 19, -1),
		(14, 21, 0), (14, 23, -1), (14, 25, 1), (14, 27, -1), (14, 29, -1),
		(14, 31, 1), (15, 1, 1), (15, 3, 0), (15, 5, 0), (15, 7, 1), (15, 9,
		0), (15, 11, 1), (15, 13, -1), (15, 15, 0), (15, 17, 1), (15, 19, -1),
		(15, 21, 0), (15, 23, -1), (15, 25, 0), (15, 27, 0), (15, 29, -1),
		(15, 31, -1)])

# Return True iff n is a prime. Algorithm uses trial division and is therefore
# only usable for 'small' n. This function is used to test the probable prime
# functions which work for 'large' n as well.
def	isPrime(n):
	if	n <= 1:
		return False
	if	(n <= 3) or (n == 5):
		return True
	if	(n & 1 == 0) or (n % 3 == 0):
		return False
	t = 5
	d = 2
	while (t * t <= n) and (n % t):
		t += d
		d = 6 - d	# skip trial divisors t with t % 3 = 0
	return n % t != 0

# Low quality primality test
# Precondition: n is odd
# For n > 2:	if result is False then n is composite
#				if result is True then n maybe prime
# 341 (= 11 * 31) is smallest composite number where function returns True
def	isProbablePrime2(n):
	return (n > 1) and (pow(2, n - 1, n) == 1)

# Test the probable prime detector 'func' on all odd numbers between
# n and upperN. Return False iff there is a case where a prime number
# is erroneously flagged as composite.
def	testisProbablePrimeFunc(func, n, upperN):
	if	n & 1 == 0:
		n += 1						# Make sure that n is odd
	while n <= upperN:
		if	func(n) < isPrime(n):	# Error if composite was prime after all
			return False
		n += 2						# Next odd
	return True

# The list of all odd primes less than 100
oddPrimes97 = filter(isProbablePrime2, range(100))
# The product of all odd primes less than 100
oddPrimeProduct97 = reduce(operator.mul, oddPrimes97)

# Good quality primality test
# Precondition: n is odd
# For n > 2:	if result is False then n is composite
#				if result if True then n maybe prime
# 42799 (= 127 * 337) is smallest composite number where function returns True
# Idea is to check the identity jacobi(2, p) = 2 ^ ((p - 1) / 2) % p
# which holds for primes (according to the Euler criterion)
# Note that isProbablePrime(1093 * 1093) = True
def	isProbablePrime(n):
	return (n > 1) and ((n < 561) or gcd(oddPrimeProduct97, n) == 1) and \
		(pow(2, n >> 1, n) == ((n & 7 in [1, 7]) or (n - 1)))
	# Use the fact that True == 1

# Return True iff n is 2 or a strong pseudo prime to base a
# Checking for strong pseudo primality is the core of the Miller-Rabin
# probabilistic prime check: if a number is a strong pseudo prime for
# sufficiently many bases, it is highly likely to be a prime. Note that this
# idea does not work with just checking a^(n-1) = 1 mod n as a Carmichael
# number c (such as 561) will satisfy this criterion for all a with gcd(a,c) = 1
def	isStrongPseudoPrime(a, n):
	if	n == 2:
		return True
	n1 = n - 1	# i.e. -1 % n
	r = n1 >> 1
	k = 1
	q = r >> 1
	m = r & 1
	while m == 0:
		k += 1
		r = q
		q = r >> 1
		m = r & 1
	# Postcondition: (n = 2^k * r + 1) and (r % 2 = 1)
	t = pow(a, r, n)
	pt = n1				# pt will hold previous value of t
	while (t != 1) and (t != n1) and k:
		pt = t			# save previous value
		t = (t * t) % n	# square modulo n
		k -= 1
	# We have a strong pseudo prime iff
	# Case 1) We reached 1 and the previous value was -1 (mod n) or
	# Case 2) We reached -1 and we have at least one squaring to go
	return (t == 1) and (pt == n1) or (t == n1) and (k > 0)
	# Note: We cannot replace (k > 0) with k as a boolean value is
	# expected.

primeProduct3 = 5*7*13*23*29*31*37*53*61*97*127*149*151*157*137*229

# Very good quality primality test (but slower than isProbablePrime)
# For n > 0:	if result is False then n is composite or 1
#				if result if True then n maybe prime
# 220729 (= 103 * 2143) is smallest composite number where function returns True
def	isProbablePrime3(n):
	return (n > 1) and ((n < 2047) or gcd(primeProduct3, n) == 1) and \
		isStrongPseudoPrime(2, n)

# Test the probable prime detector 'func' on all odd numbers between
# n and upperN. Return False iff there is a discrepancy between
# 'func' and isPrime
def	testisProbablePrimeFuncStrict(func, n, upperN):
	if	n & 1 == 0:
		n += 1						# Make sure that n is odd
	while n <= upperN:
		if	func(n) != isPrime(n):	# Error if functions disagree
			print 'Prime error for %i. Got %s which is not correct.' \
				% (n, func(n))
			return False
		n += 2						# Next odd
	return True

# Probable prime check to be used. Note that correctness of algorithms in this
# module only depends on the fact that composite numbers are detected correctly.
useIsProbablePrime = isProbablePrime	# productive use
#useIsProbablePrime = isProbablePrime	# productive use
#useIsProbablePrime = isProbablePrime2	# testing
#useIsProbablePrime = lambda x: x > 1	# testing
#useIsProbablePrime = isProbablePrime3	# testing

# Performance evaluation
# Case 'small':		time decompose.py 0 100000 f
# Case 'medium':	time decompose.py 'sys.maxint-500L' 100000 f
# Case 'large':		time decompose.py '10**200' 50 f
#
# (Mac OS X 10.3.8, 1.5GHz MHz PowerPC G4, 256 KB L2 Cache,  2MB L3 Cache,
# 1.5GB Memory, Python 2.3 (#1, Sep 13 2003, 00:49:11)
# [GCC 3.3 20030304 (Apple Computer, Inc. build 1495)] on darwin )
#						small			large		total
# isProbablePrime		0:11.47			0:05.45		16.92
# isProbablePrime2		0:10.08			0:27.89		37.97
# lambda x: x > 1		0:10.90			0:27.73		38.63
# isProbablePrime3		0:13.44			0:13.66		27.10


# Cache for the odd primes less than 500
oddPrimesCache = filter(isProbablePrime, range(500))

# Return the factorial of n
def	fac(n):
	return reduce(operator.mul, range(1, n + 1), 1)

# Return the product of the first n primes
# pp(0) = 1, pp(1) = 2, pp(2) = 6, ...
def	pp(n):
	if	n > 0:
		return reduce(operator.mul, [p for p in oddPrimes(n - 1)], 1) << 1
	return 1

def	testpp():
	return testfunc(pp, [(-10, 1), (-1, 1), (0, 1), (1, 2), (2, 6), (3, 30),
		(9, 223092870)])

# Return the smallest probable prime p>=n with p % (m/gcd(m,r))=(r/gcd(m,r))
def	dp(n, m, r):
	g = gcd(m, r)
	m /= g
	p = m * (n / m) + r / g
	if	p < n:
		p += m
	while not isProbablePrime(p):
		p += m
	return p

def	testdp():
	return testfunc(dp, [(100, 4, 1, 101), (101, 4, 1, 101), (100, 6, 4, 101),
		(101, 6, 4, 101)])

# Return next probable prime >= n
# Precondition: n is odd
def	nextProbablePrime(n):
	while not useIsProbablePrime(n):
		n += 2
	return n

# Return next probable prime >= n
def	np(n):
	if	n <= 2:
		return 2
	return nextProbablePrime((n & 1) and n or (n + 1))

# For given even k and odd prime p, return True if n = k * p + 1 is prime.
# If True is returned, n is guaranteed to be prime but note that the result
# might be False even though n is prime.
def	isnpk(k, p):
	n = k * p + 1
	if	gcd(n, oddPrimeProduct97) > 1:
		return n in oddPrimes97		# in case n is a prime less than 100
	t = pow(2, k, n)
	if	t == 1:
		return False
	return pow(t, p, n) == 1

def	testisnpk():
	return testfunc(isnpk, [(4, 13, True), (2, 5003, True), (4, 5003, False),
		(2, (1L << 31) - 1, False), (46, (1L << 31) - 1, True), (32, 3, True),
		(20, 5, True), (22, 5, False)])

# For given k and odd prime p return K >= k such that n = K * p + 1 is prime.
# Note that n is then guaranteed to be prime but K is not necessarily the
# smallest value >= k to make this happen. Note also that Dirichlet's theorem
# guarantees the existence of such a prime (but this algorithm might fail
# for all such primes ...)
def	npk(k, p):
	if	k & 1:
		k += 1	# k is now even
	while not isnpk(k, p):
		k += 2
	return k

# Generator for the odd primes
def	oddPrimes(limit = -1):
	index = 0
	while (limit < 0) or (index < limit):
		if	index >= len(oddPrimesCache):
			oddPrimesCache.append(nextProbablePrime(oddPrimesCache[-1] + 2))
		yield oddPrimesCache[index]
		index += 1

# Probabilistic check whether n is a square. If the result is (False, q) then n
# cannot be a square and (q / n) = -1. If the result is (True, 0), then n may
# or may not be a square.
# The idea is to compute the jacobi symbol (q / n) for 'certainty' many odd
# primes q. Since (q / n1 * n2) = (q / n1) * (q / n2), the jacobi symbol (q / n)
# is always 1 if n is a square. This also means that if we can find a q such
# that (q / n) = -1 then n cannot be a square.
# Heuristically each additional q filters out above half of the non-squares.
# The number n = 182919 is the smallest non-square for which
# isSquareProbabilistic(n, 15) returns True, 0
# The number n = 8042479 is the smallest non-square for which
# isSquareProbabilistic(n, 30) returns True, 0
def	isSquareProbabilistic(n, certainty):
	generator = oddPrimes()
	while certainty:
		q = generator.next()
		if	jacobi(n % q, q) == -1:		# q is a witness that n is not a square
			return False, q
		certainty -= 1
	return True, 0

# There are exactly 336 squares mod 10080. This is the smallest rate of squares
# for all n < 15840.
magicN = 10080
squaresModMagicN = {}.fromkeys([(i * i) % magicN for i in range(magicN >> 1)])
# If result is True then n may or may not be a square. If the result is False
# then n cannot be a square. The 'false positive' rate is 3.3% = 336 / 10080 =
# 1 / 30. The smallest non-square for which isProbableSquare(n) = True is 385.
def	isProbableSquare(n):
	return (n % magicN) in squaresModMagicN

def	testisProbableSquare(low, high):
	while low <= high:
		if	not isProbableSquare(low) and (isqrt(low)[1] == 0):
			return False
		low += 1
	return True

# Compute an imaginary unit modulo p
#	Precondition: p % 4 = 1
#	Postcondition: p is prime implies: Result is (x, False) and x^2 % p = -1
#	The result can also be (x, True) and then x^2 = p
#	Note that this algorithm might succeed even when the argument is not prime.
#	Example (1)
#		n = 3277 = 29 * 113 % 8 = 5, 2^((n-1)/4) = 2^819 = 128 mod n
#		128^2 % n = -1
#	Explanation:
#		order(2) mod 29 = order(2) mod 113 = order(2) mod n = 28 divides n - 1
#		This implies: 2^(n-1) mod 29 = 2^(n-1) mod 113 = 1
#		We also have 2^((n-1)/2) mod 29 = 2^((n-1)/2) mod 113 = -1
#		overall 2^((n-1)/2) % n = -1
#	Example (2)
#		p = 3281 = 17 * 193 % 8 = 1, jacobi(3, p) = -1
#		3^((p-1)/4) = 3^820 = 81 mod p, 81^2 = -1 mod p
#	Example (3)
#		p = 49141 = 157 * 313 % 8 = 5, 2^((p-1)/4) = 2^12285 = 32527 mod p
#		32527^2 = -1 mod p, isProbablePrime(p) = True
#	Example (4)
#		p = 665281 = 577 * 1153 % 8 = 1, jacobi(13, p) = -1
#		13 ^ ((p-1)/4) = 13 ^ 166320 = 531393 mod p
#		531393^2 = -1 mod p, isProbablePrime(p) = True
#	Note also that if p is a square, jacobi(q, p) = 1 for all q
def	iunit(p):
	if	p & 7 == 5:
		q = 2
	else:
		primes = oddPrimes()
		q = primes.next()						# q is an odd (probable) prime
		# (q % 2 = 1) and (p % 4 = 1) implies jacobi(q, p) = jacobi(p % q, q)
		while jacobi(p % q, q) == 1:			# jacobi(q, p)
			q = primes.next()
			if	(q == 229) and isProbableSquare(p):# loop is running quite long
				# reached for p = dp(1, 4*pp(k), 1) for k > 47 or p = 1093 ** 2
				s, r = isqrt(p)					# check, if p is a square
				if	r == 0:						# if yes, return square root
					return s, True
	return pow(q, p >> 2, p), False

# Test the iunit function for arguments between p and upperP making sure
# that the argument is a (probable) prime congruent 1 modulo 4
# Returns True if no error has been detected
def	testiunit(p, upperP):
	p = ((p >> 2) << 2) + 1	# Make sure that p % 4 = 1
	upperP = min(upperP, 42799)	# and that upperP does not exceed range where
	while p <= upperP:			# isProbablePrime works correctly.
		if	isProbablePrime(p):
			if	(iunit(p)[0] ** 2 + 1) % p:	# This is the check
				return False
		p += 4					# maintain invariant p % 4 = 1
	return True

ln2 = math.log(2)

# Returns the smallest integer greater or equal to the logarithm of n to base 2,
# i.e. the result r satisfies 2^r <= n < 2^(r+1).
def	floorLog2(n):
	r = int(0.5 + math.log(n) / ln2)
	return ((1L << r) <= n) and r or (r - 1)

# The square root algorithm uses its iterative variant for numbers less than
# 2^1024. For larger numbers the recursive case is invoked.
isqrtIterativeBetter = 1L << 1024

# Input:	n >= 0, log2n = floor(log(2, n)), 2^log2n <= n < 2^(log2n + 1)
# Output:	(s, r) where (s-1)^2 <= n < (s+1)^2 and s^2 + r = n
# For very small n, the built-in square root function is invoked. For larger n
# (typically n < 10^300) an iterative algorithm is used while for the largest
# n, a divide & conquer approach is employed almost identical to the one from
# Paul Zimmermann (Karatsuba Square Root, http://www.inria.fr/rrrt/rr-3805.html)
# The difference is that a slightly weaker invariant ((s-1)^2 <= n < (s+1)^2
# can be shown to suffice - note that the r = n - s^2 can be negative in the
# case that the square root is over estimated.
def	isqrtInternal(n, log2n):
	if	n <= sys.maxint:
		s = int(math.sqrt(n))
		return s, n - s * s
	if n < isqrtIterativeBetter:
		d = 7 * (log2n / 14 - 1)
		q = 7
#		assert (0 < (n >> (d + d)) < (1 << 28)) and (q <= d)
		s = int(math.sqrt(n >> (d + d)))
		while d:
#			assert (s - 1) ** 2 <= (n >> (d + d)) < (s + 1) ** 2
			if	q > d:
				q = d
			s <<= q
			d -= q
			q += q
			s = (s + (n >> (d + d)) / s) >> 1
		return s, n - s * s
	log2b = log2n >> 2
	mask = (1L << log2b) - 1L
	s, r = isqrtInternal(n >> (log2b + log2b), log2n - (log2b + log2b))
	q, u = divmod((r << log2b) + ((n >> log2b) & mask), s + s)
	return (s << log2b) + q, (u << log2b) + (n & mask) - q * q

# Input:	n >= 0
# Output:	(s, r) where s^2 <= n < (s+1)^2 and s^2 + r = n
def	isqrt(n):
	assert n >= 0
	if	n <= sys.maxint:
		s = int(math.sqrt(n))
		return s, n - s * s
	s, r = isqrtInternal(n, floorLog2(n))
	return (r < 0) and (s - 1, r + s + s - 1) or (s, r)


# Test the isqrt function for arguments between n and upperN
# Returns True if no error has been detected
def	testisqrt(n, upperN):
	while n <= upperN:
		s, r = isqrt(n)
		if	not ((s * s <= n < (s + 1) ** 2) and (s * s + r == n)):
			return False	# return False iff postcondition of isqrt not met
		n += 1
	return True

# Try to decompose n into a sum of two squares
# Precondition: n is a probable prime, n % 4 = 1
#	(a, b, True) with a^2 + b^2 = n iff decomposition was successful
#	(0, 0, False) iff decomposition was not successful
def	decomposeProbablePrime(n):
	b, r = iunit(n)
	if	r:
		return 0, b, True
	if	(b * b + 1) % n:		# Check whether we got an imaginary unit
		return 0, 0, False		# Indicate failure if not
	a = n
	while b * b > n:
		a, b = b, a % b
	return b, a % b, True

# Perform n tests starting at the smallest prime p >= start with p % 4 = 1
def	testdecomposeProbablePrime(start, n):
	p = ((start >> 2) << 2) + 1
	if	p < start:
		p += 4
	while n:
		while not isProbablePrime(p):
			p += 4
		a, b, c = decomposeProbablePrime(p)
		if	c and (a * a + b * b != p):
			return False
		n -= 1
		p += 4
	return True

# Dictionary of exceptional cases the search in decompose cannot handle
decomposeExceptions = {
	9634:	[56, 57, 57],	2986:	[21, 32, 39],	1906:	[13, 21, 36],
	1414:	[ 6, 17, 33],	 730:	[ 0,  1, 27],	 706:	[15, 15, 16],
	 526:	[ 6,  7, 21],	 370:	[ 8,  9, 15],	 226:	[ 8,  9,  9],
	 214:	[ 3,  6, 13],	 130:	[ 0,  3, 11],	  85:	[ 0,  6,  7],
	  58:	[ 0,  3,  7],	  34:	[ 3,  3,  4],	  10:	[ 0,  1,  3],
	   3:	[ 1,  1,  1],	   2:	[ 0,  1,  1]							}

# Decompose an integer n>=0 into a sum of up to four squares. Result is a
# tuple where the first entry is a list of four integers and the second
# entry is True iff the search loop was successful. Note that currently
# there is no known input where the search loop would not be successful
# but there is no known proof.
def	decompose(n):

	# Multiply all elements of l with v and return a tuple with the sorted list
	# and the value True indicating success
	def	sortScaled(l):
		l.sort()
		return [v * x for x in l], True
	
	assert n >= 0
	if	n <= 1:								# Done if n = 0 or n = 1
		return [0, 0, 0, n], True
	v = 1									# Remove powers of 4
	while n & 3 == 0:						# n % 4 = 0
		n >>= 2								# n = n / 4
		v += v
	# Postcondition: (nOld = v^2*n) and (n%4 != 0) and (v = 2^k for some k >= 0)
	sq, p = isqrt(n)
	if	p == 0:								# n is a square
		return [0, 0, 0, v * sq], True
	if	(n & 3 == 1) and useIsProbablePrime(n):	# n is prime, n % 4 = 1
		s, r, done = decomposeProbablePrime(n)
		if	done:							# otherwise n was not a prime
			return sortScaled([0, 0, s, r])
	if	n & 7 == 7:		# Need 4 squares, subtract largest square delta^2
						# such that (n > delta^2) and (delta^2 % 8 != 0)
		delta, n = sq, p
		if	sq & 3 == 0:
			delta -= 1
			n += delta + delta + 1
		# sq % 4  = 0 -> delta % 8 in [3, 7]			 ->
		#	delta^2 % 8 = 1		  -> n % 8 = 6
		# sq % 4 != 0 -> delta % 8 in [1, 2, 3, 5, 6, 7] ->
		#	delta^2 % 8 in [1, 4] -> n % 8 in [3, 6]
		# and this implies n % 4 != 1, i.e. n cannot be a sum of two squares
		sq, p = isqrt(n)
		# sq^2 != n since n % 4 = 3 which is never true for a square
	else:
		delta = 0
	# Postcondition: (sq = isqrt(n)) and (n % 8 != 7) and (n % 4 != 0) and
	#	(nOld = v^2 * (n + delta^2))
	# This implies that n is a sum of three squares - now check whether n
	# is one of the special cases the rest of the algorithm could not handle.
	if	n in decomposeExceptions:
		# Retrieve pre-computed result and scale with v
		return sortScaled([delta] + decomposeExceptions[n])
	# Now perform search distinguishing two cases noting that n % 4 != 0
	# Case 1: n % 4 = 3, n = x^2 + 2*p, p % 4 = 1,
	#	p prime, p = y^2 + z^2 implies n = x^2 + (y + z)^2 + (y - z)^2
	if	n & 3 == 3:
		if	sq & 1 == 0:
			sq -= 1
			p += sq + sq + 1
		p >>= 1
		while True:
			if	useIsProbablePrime(p):
				r0, r1, done = decomposeProbablePrime(p)
				if	done:
					return sortScaled([delta, sq, r0 + r1, abs(r0 - r1)])
			sq -= 2							# Next sq
			if	sq < 0:						# Should not happen, no known case
				return 4 * [0], False
			p += sq + sq + 2				# Next p
	# Case 2: n % 4 = 1 or n % 4 = 2, n = x^2 + p,
	#	p % 4 = 1, p prime, p = y^2 + z^2 implies n = x^2 + y^2 + z^2
	if	(n - sq) & 1 == 0:
		sq -= 1
		p += sq + sq + 1
	while True:
		if	useIsProbablePrime(p):
			r0, r1, done = decomposeProbablePrime(p)
			if	done:
				return sortScaled([delta, sq, r0, r1])
		sq -= 2								# Next sq
		if	sq < 0:							# Should not happen, no known case
			return 4 * [0], False
		p += 4 * (sq + 1)					# Next p

# Decompose all integers from list li into at most four squares and print
# the results iff verbose = True. The result is a list of all cases where the
# decomposition was not successful. Note that this list should be empty.
def	checkDecompose(li, verbose):
	f = []
	for i in li:
		r, done = decompose(i)
		if	verbose:	# Use the fact that r is sorted
			if	r[0]:	# Need four squares
				s = '%i = %i^2 + %i^2 + %i^2 + %i^2' % (i, r[0], r[1],
					r[2], r[3])
			elif r[1]:	# Need three squares
				s = '%i = %i^2 + %i^2 + %i^2' % (i, r[1], r[2], r[3])
			elif r[2]:	# Need two squares
				s = '%i = %i^2 + %i^2' % (i, r[2], r[3])
			else:		# Number is a square
				s = '%i = %i^2' % (i, r[3])
			# print also number of squares needed
			print '%s  # %i' % (s, 4 - r[:-1].count(0))
		if	not done or (sum([x*x for x in r]) != i):
			f.append((i, r, done))
	return f

# Perform a small self test of the major function.
# Return True iff all tests successful.
def	selfTest():
	return (testgcd() and
		testisProbablePrimeFunc(isProbablePrime2, 1, 1000) and
		testisProbablePrimeFunc(isProbablePrime, 1, 1000) and
		testjacobi() and
		testisqrt(0, 125) and
		testisqrt(10**20 + random.randint(0, 10**19), 20) and
		testiunit(5, 2377) and
		(iunit(1093 ** 2)[0] == 1093) and
		testisProbablePrimeFuncStrict(isProbablePrime3, 3, 1000) and
		testisProbablePrimeFuncStrict(isProbablePrime, 3, 1000) and
		testisnpk() and
		testpp() and
		testdecomposeProbablePrime(5, 100) and
		testdecomposeProbablePrime(10 ** 5 + 1, 3) and
		testisProbableSquare(100, 400) and
		(len(checkDecompose([dp(1, 4 * pp(48), 1)], False)) == 0) and
		testdp()
	)


def	main():

	# Print usage information for the script and exit.
	def	usage():
		print '''\
Usage: %s start(Exp) [iterations(Exp)] [v(char)] [f(char)]
Decomposes the integers in start (if start evaluates to a list) or in
[start, start + iterations - 1] (if start evaluates to an integer)
into the sum of at most 4 squares.

Expression can contain the following functions:
  gcd(a,b):    greatest common divisor of a and b
  jacobi(a,b): the Jacobi symbol of a and b
  fac(n):      factorial of n
  pp(n):       product of the first n primes [pp(0)=1, pp(1)=2, pp(2)=6, ...]
  dp(n,m,r):   smallest probable prime p >= n with p mod m/gcd(m,r)=r/gcd(m,r)
  np(n):       smallest probable prime p >= n
  isqrt(n)[0]: integer square root of n is y with y^2 <= n < (y + 1)^2

v: verbose  f: fast (omit self test)

Examples:
  decompose.py 10007
  decompose.py '577*1153'
  decompose.py 'np(19081961*10**3)' 2 v
  decompose.py '[2*10**i+19081961 for i in [34, 35, 36]]' v
  time decompose.py 0 100000
''' % sys.argv[0]
		sys.exit(2)
		# Called because some form of command line syntax error detected

	# Return the value of 'intString' if it contains a valid expression.
	# Otherwise print 'errorMessage', the usage information and exit.
	def	getInt(intString, errorMessage):
		try:
			return eval(intString)
		except:
			print errorMessage % intString
			usage()

	# Return True iff string 'opt' is in the lower case version
	# of the script's arguments.
	def	hasOption(opt):
		return opt in [x.lower() for x in sys.argv]

	if	not (2 <= len(sys.argv) <= 5):
		usage()
	if	not (hasOption('f') or selfTest()):
		print 'Self test failed! Exiting...'
		sys.exit(1)
	li = getInt(sys.argv[1], 'Illegal expression \'%s\' for start.')
	verbose = hasOption('v')
	if	not isinstance(li, list):
		# Create list of numbers to check.
		# If number of iterations is 0, use 1 instead.
		li = range(li, li + ((len(sys.argv) > 2) and
			not sys.argv[2].lower() in ['f', 'v'] and
			getInt(sys.argv[2],
				'Illegal expression \'%s\' for number of iterations.') or 1))
	r = checkDecompose(li, verbose or (len(li) == 1))
	if	len(r):
		print 'Errors: ', r

def get_rs(n):
	r = decompose(n);
	print("test")
	result = [str(i) for i in r[0]]
	return result

if	__name__ == '__main__':
	main();
