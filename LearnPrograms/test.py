first = int(input()) #Не используется
nums = input().split()
result = int(input())

first_num = -1
second_num = -1

results = []

for i in nums:
    if first_num == -1:
        first_num = int(i)
    if second_num == -1:
        second_num = int(i)

    if second_num != -1 and first_num != -1:
        if second_num + first_num == result:
            results.append(1)
        else:
            results.append(0)