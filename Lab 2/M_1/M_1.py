CHUNK_SIZE = 8

with open('Lab 2/M_1/8.txt', 'r') as file:
    lines = file.readlines()

for line in lines:
    stripped_line = line.strip()
    chunks = [stripped_line[i:i+CHUNK_SIZE]
              for i in range(0, len(stripped_line), CHUNK_SIZE*2)]
    if (len(chunks) > len(set(chunks))):
        print("duplicate found:")
        print(stripped_line)
