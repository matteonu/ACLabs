from hashlib import md5


with open('Lab 5/M2/rockyou.txt', 'r', encoding='latin-1') as file:
    for line in file:
        try:
            hash = md5(line.strip().encode()).hexdigest()
            if hash == '9fb7009f8a9b4bc598b4c92c91f43a2c':
                print(line)
        except:
            continue