import socket
import hashlib
from threading import Thread
from tkinter import *
from tkinter import messagebox
import datetime
import psycopg2
import random
import math
import numpy as np
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# окно
window = Tk()
window.title('Регистрация')
window.geometry('300x200')
window.resizable(0, 0)
window['bg'] = "#f2e3f4"

reply = 0  # ответ, который нужно отправить клиенту

count = 1

K = ""


def Time():
    t = datetime.datetime.now().date()
    t_string = str(t)
    return t_string


def Lifetime():
    l = datetime.date.today() + datetime.timedelta(days=5)
    l_string = str(l)
    return l_string


def auth(username):
    global reply
    # подключение к бд
    connect = psycopg2.connect(database="ClientServer", user="postgres", password="1123581321", host="localhost",
                               port="5432")
    connect.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = connect.cursor()

    # проверяем наличие пользователя с таким же логином
    request = 'select exists(select * from users where name=\'' + username + '\');'
    cursor.execute(request)
    result = cursor.fetchall()

    # если true, то пользователь найден
    isFind = ""
    for row in result:
        isFind = str(row)
    if isFind == "(True,)":
        rows = 'select id from users where name=\'' + username + '\';'
        cursor.execute(rows)
        res = cursor.fetchall()
        user_id = res[0]
        id = ""
        for j in map(str, user_id):
            id = j
        current_date = datetime.datetime.now().date()
        current_date_string = str(current_date)
        check_time = 'select * from timestamps where id=\'' + id + '\' and lifetime>\'' + current_date_string + '\';'
        cursor.execute(check_time)
        cc = cursor.fetchall()
        time = ""
        for i in cc:
            time = i[1]
        if time == "":
            time = Time()
            lifetime = Lifetime()
            T = hashlib.md5(time.encode())
            tt = T.hexdigest()
            sql = 'insert into timestamps (id, timestamp, lifetime) values (\'' + id + '\', \'' + tt + '\', \'' + lifetime + '\');'
            cursor.execute(sql)
        reply = time
    if isFind == "(False,)":
        reply = -1

    return reply


# нажали 'Зарегистрироваться'
def clicked():
    # получаем логин и пароль
    username = username_entry.get()
    password = password_entry.get()
    hash = hashlib.md5(password.encode())
    hash_password = hash.hexdigest()
    # подключение к бд
    connection = psycopg2.connect(database="ClientServer", user="postgres", password="1123581321", host="localhost",
                                  port="5432")
    connection.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = connection.cursor()
    # проверяем наличие пользователя с таким же логином
    request = 'select exists(select * from users where name=\'' + username + '\');'
    cursor.execute(request)
    result = cursor.fetchall()
    t = ""
    for row in result:
        t = str(row)
        print(t)
    if t == "(True,)":
        messagebox.showinfo("Info", "Уже имеется клиент с данным логином")
    if t == "(False,)":
        sql = 'insert into users (name, password) values (\'' + username + '\',\'' + hash_password + '\');'
        cursor.execute(sql)
        messagebox.showinfo("Успешно зарегистрирован",
                            '{username}, {hash_password}'.format(username=username, hash_password=hash_password))


def factorisation(s, n):
    # Print the number of 2s that divide n
    while (n % 2 == 0):
        s.add(2)
        n = n // 2
    # n must be odd at this point. So we can
    # skip one element (Note i = i +2)
    for i in range(3, int(math.sqrt(n)), 2):
        # While i divides n, print i and divide n
        while n % i == 0:
            s.add(i)
            n = n // i
    # This condition is to handle the case
    # when n is a prime number greater than 2
    if n > 2:
        s.add(n)


def findPrimitive(n):
    s = set()
    phi = n - 1
    # Факторизация функции Эйлера
    factorisation(s, phi)
    # Проходим по всем числам от 2 до фи
    for r in range(2, phi + 1):
        # Iterate through all prime factors of phi.
        # and check if we found a power with value 1
        flag = False
        for it in s:
            # Check if r^((phi)/primefactors)
            # mod n is 1 or not
            if pow(r, phi // it, n) == 1:
                flag = True
                break
        # If there was no power with value 1.
        if not flag:
            return r
    # If no primitive root found
    return -1


# Функция для символа Якоби (символ Якоби определен только для нечетных чисел n)
def J(a, b):
    # Инициализация
    r = 1
    while a != 0:
        t = 0
        # Избавление от чётности
        while a % 2 == 0:
            t += 1
            a /= 2
        if t % 2 != 0:
            # Мультипликативность символа Якоби
            if b % 8 == 3 or b % 8 == 5:
                r = -r
        # Квадратичный закон взаимности
        if a % 4 == b % 4 == 3:
            r = -r
        c = a
        a = b % c
        b = c
    return r


# Тест Соловея-Штрассена
def test(p, k):
    for i in range(1, k + 1):
        a = random.randint(3, p - 2)
        if math.gcd(a, p) != 1:
            return 0
        if pow(a, int((p - 1) / 2), p) != J(a, p):
            if pow(a, int((p - 1) / 2), p) - p == J(a, p):
                continue
            return 0
    return 1


def generate_P(x):
    while True:
        p = random.getrandbits(x)
        if p % 2 == 0:
            continue
        if test(p, 4) != 0:
            print(p)
            return p


# Инициализация S-блока
def KSA(key):
    s_box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s_box[i] + ord(key[i % len(key)])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    # print(type(s_box)) #for_test
    return s_box


# Генерация псевдослучайного слова K
def PRGA(plain, box):
    res = []
    i = j = 0
    for s in plain:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        t = (box[i] + box[j]) % 256
        k = box[t]
        res.append(chr(ord(s) ^ k))

    cipher = "".join(res)
    return cipher


def RSA():
    p, q = generate_P(16), generate_P(16)
    while p == q:
        q = generate_P(80)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 2
    while math.gcd(e, phi) != 1:
        e += 1
    d = bezout(e, phi)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key


# Подсчёт количества итераций для алгоритма Евклида
def NumOfRows(a, b):
    rows = 1
    mod = a % b
    while mod != 0:
        a = b
        b = mod
        mod = a % b
        rows += 1
    return rows


# Расширенный алгоритм Евклида
def Nod(a, b, euler):
    rows = NumOfRows(a, b)
    mt = np.zeros((rows, 6))
    mod = a % b
    div = a / b
    mt[0, 0] = a
    mt[0, 1] = b
    mt[0, 2] = mod
    mt[0, 3] = div

    for i in range(1, rows):
        mt[i, 0] = b
        a = mt[i, 0]
        mt[i, 1] = mod
        b = mt[i, 1]
        mt[i, 2] = mt[i, 0] % mt[i, 1]
        mod = mt[i, 2]
        mt[i, 3] = mt[i, 0] / mt[i, 1]
        div = mt[i, 3]
    for i in range(rows - 1, -1, -1):
        if i == rows - 1:
            mt[i, 4] = 0
            mt[i, 5] = 1
            continue
        mt[i, 4] = mt[i + 1, 5]
        mt[i, 5] = mt[i + 1, 4] - mt[i + 1, 5] * mt[i, 3]

    if mt[0, 5] < 0:
        d = mt[0, 5] + euler
    else:
        d = mt[0, 5]
    return d


def bezout(a, b):
    x, xx, y, yy = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a % b
        x, xx = xx, x - xx*q
        y, yy = yy, y - yy*q

    return x if x > 0 else x + b


def create_chat():
    global window
    global List
    global font
    global font2
    for i in List:
        i.destroy()
        window.update()
    List.clear()
    window.title('Чат с клиентом')
    window.geometry('400x500')
    window.resizable(0, 0)
    window['bg'] = "#f2e3f4"
    text = Text(width=25, height=10, font=font)
    text.pack(side=TOP)
    List.append(text)
    text2 = Text(width=18, height=7, font=font2)
    text2.place(x=200, y=370)
    List.append(text2)
    scroll2 = Scrollbar(command=text.yview)
    scroll2.pack(side=RIGHT, fill=Y)
    text2.config(yscrollcommand=scroll2.set)
    scroll = Scrollbar(command=text.yview)
    scroll.pack(side=LEFT, fill=Y)
    text.config(yscrollcommand=scroll.set)
    entry = Entry(window, font=font)
    entry.place(x=35, y=310)
    List.append(entry)
    button = Button(window, text="Отправить", font=font, command=send_message)
    button.place(x=35, y=420)
    List.append(button)


def send_message():
    global count
    message = List[2].get()
    box = KSA(K)
    cipher_message = PRGA(message, box)
    List[0].insert(float(count), "Server: " + message + "\n" + "Server (encrypted): " + cipher_message + "\n")
    count += 2
    client_socket.send(cipher_message.encode())


def listen_user(user):
    global count
    while True:
        data = user.recv(2048).decode("utf-8")
        box = KSA(K)
        decrypted_message = PRGA(data, box)
        # Если отправили файл
        if decrypted_message[len(data) - 1] == "\t":
            List[1].insert(float(count), decrypted_message[:len(data) - 1] + '\n')
            count += 1
            public_key, private_key = RSA()
            public = str(public_key[0]) + " " + str(public_key[1])
            print(decrypted_message)
            h = hashlib.md5(decrypted_message.encode()).digest()
            hash1 = str(int.from_bytes(h, 'big'))
            client_socket.send(public.encode())
            data = int(user.recv(2048).decode("utf-8"))
            print(data)
            hash2 = pow(int(data), int(private_key[0]), private_key[1])
            hash2 = str(hash2)
            List[1].insert(float(count), "Hash1: " + hash1 + '\n' + "Hash2: " + hash2)
            count += 2
        else:
            List[0].insert(float(count), "Client (decrypted): " + decrypted_message + "\n" + "Client: " + data + "\n")
            count += 2


# сокет, чтобы получать данные от клиента
server_socket = socket.socket()
server_socket.bind(("localhost", 9090))
server_socket.listen(10)

# принять подключение с помощью метода accept
(client_socket, client_adress) = server_socket.accept()

# Виджеты окна регистрации

List = []

font = ("Century Gothic", 16)
font2 = ("Courier New", 10)

username_label = Label(window, text="Логин", font=font)
username_label.pack()
List.append(username_label)

username_entry = Entry(window, font=font)
username_entry.pack()
List.append(username_entry)

password_label = Label(window, text="Пароль", font=font)
password_label.pack()
List.append(password_label)

password_entry = Entry(window, font=font)
password_entry.pack()
List.append(password_entry)

send_button = Button(window, text="Зарегистрировать", command=clicked, font=font)
send_button.place(x=35, y=140)
List.append(send_button)


def Listen():
    global K
    # получаем логин клиента
    username = client_socket.recv(1024).decode("utf8")
    reply = auth(username)

    # отправляем метку t
    client_socket.send(str(reply).encode())

    # получаем password клиента + метка t
    pass_t_c = client_socket.recv(1024).decode("utf8")

    # подключение к бд
    connection = psycopg2.connect(database="ClientServer", user="postgres", password="1123581321", host="localhost",
                                  port="5432")
    connection.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = connection.cursor()
    sql = 'select password from users where name=\'' + username + '\';'
    cursor.execute(sql)
    pp = cursor.fetchall()
    pass_s = ""
    for k in pp:
        pass_s = k[0]
    pass_t_s = pass_s + reply
    hh = hashlib.md5(pass_t_s.encode())
    pass_t_server = hh.hexdigest()
    answer = ""
    # print("client", pass_t_c)
    # print("server", pass_t_server)
    if pass_t_c == pass_t_server:
        answer = "Авторизация прошла успешно"
        client_socket.send(str(answer).encode())

        # Генерим a, p, g, A
        a = random.getrandbits(16)
        p = generate_P(16)
        g = findPrimitive(p)
        A = pow(g, a, p)

        # Отсылаем p, g, a
        client_socket.send(str(g).encode("utf-8"))
        client_socket.recv(2048).decode("utf-8")
        client_socket.send(str(p).encode("utf-8"))
        client_socket.recv(2048).decode("utf-8")
        client_socket.send(str(A).encode("utf-8"))
        client_socket.recv(2048).decode("utf-8")

        # Получаем B
        B = int(client_socket.recv(2048).decode("utf-8"))
        messagebox.showinfo("Server receive", f"B = {B}")

        # Генерируем K
        K = str(pow(B, a, p))
        print(K)

        with open("stats.txt", "w") as stats:
            stats.write(f"{g}, {A}, {p}, {B}, {K}")

        # Чат
        create_chat()
        thread = Thread(target=listen_user, args=(client_socket,))
        thread.start()
    else:
        answer = "Чёт не то"
        client_socket.send(str(answer).encode())

    # client_socket.close()
    # server_socket.close()


th = Thread(target=Listen)
th.start()

window.mainloop()
