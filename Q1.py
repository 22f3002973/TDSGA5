import json
from collections import deque

# Load maze
with open("maze-solve.json", "r") as f:
    maze = json.load(f)

width = maze["width"]
height = maze["height"]
openMask = maze["openMask"]

sx, sy = maze["start"]
ex, ey = maze["end"]

# (Move Letter, dx, dy, Bit)
DIRS = [
    ("U", 0, -1, 1),
    ("R", 1, 0, 2),
    ("D", 0, 1, 4),
    ("L", -1, 0, 8),
]

start = (sx, sy)
end = (ex, ey)

queue = deque([start])
parent = {start: None}

while queue:
    x, y = queue.popleft()

    if (x, y) == end:
        break

    mask = openMask[y][x]

    for letter, dx, dy, bit in DIRS:
        if mask & bit:
            nx = x + dx
            ny = y + dy

            if (nx, ny) not in parent:
                parent[(nx, ny)] = (x, y, letter)
                queue.append((nx, ny))

# Reconstruct path
moves = []
cur = end

while parent[cur] is not None:
    px, py, letter = parent[cur]
    moves.append(letter)
    cur = (px, py)

moves.reverse()

answer = "".join(moves)

print(answer)
print("Length:", len(answer))