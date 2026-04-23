"""Challenge 58: Pollard's Method for Catching Kangaroos."""
import random
import hashlib
from crypto_utils import invmod

# Use small parameters for tractability
p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
q = 335062023928212862163391285677693
g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357

# Bob's secret key in a known range [a, b]
a_bound = 0
b_bound = 2**20  # small range for demonstration
secret = random.randint(a_bound, b_bound)
y = pow(g, secret, p)


def pseudorandom_map(y_val, k):
    """Deterministic map from group element to step size."""
    h = int(hashlib.sha256(str(y_val).encode()).hexdigest(), 16)
    return pow(2, h % k)


def kangaroo(g, y, p, a, b, k=20):
    """Pollard's kangaroo algorithm for discrete log in [a, b]."""
    # Tame kangaroo
    N = int((b - a) ** 0.5) * 4  # number of steps

    xT = 0
    yT = pow(g, b, p)
    for _ in range(N):
        step = pseudorandom_map(yT, k)
        xT += step
        yT = (yT * pow(g, step, p)) % p

    # Wild kangaroo
    xW = 0
    yW = y
    while xW < b - a + xT:
        step = pseudorandom_map(yW, k)
        xW += step
        yW = (yW * pow(g, step, p)) % p
        if yW == yT:
            return b + xT - xW

    return None


print(f"Searching for discrete log in range [0, {b_bound}]...")
result = kangaroo(g, y, p, a_bound, b_bound)

if result is not None:
    print(f"Found: {result}")
    print(f"Actual: {secret}")
    assert result == secret
    print("Pollard's kangaroo method succeeded!")
else:
    # Retry with different parameters
    print("First attempt failed, retrying...")
    for _ in range(5):
        result = kangaroo(g, y, p, a_bound, b_bound, k=15)
        if result is not None:
            print(f"Found: {result}")
            assert result == secret
            print("Pollard's kangaroo method succeeded!")
            break
    else:
        print("Kangaroo search did not converge (may need more iterations)")
