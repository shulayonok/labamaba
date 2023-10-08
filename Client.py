import socket
import hashlib
import random
import struct
from tkinter import *
from tkinter import messagebox
from threading import Thread
import tkinter.filedialog as fd

# окно
window = Tk()
window.title('Авторизация')
window.geometry('300x200')
window.resizable(0, 0)
window['bg'] = "#f2e3f4"

count = 1
filename = ""

K = ""

isFile = False
hash_text = ""

# Подключаемся к серверу
client = socket.socket()
client.connect(("localhost", 9090))


def read_file():
    if choose_file():
        with open(filename, "r") as file:
            content = file.read()
            content += "\t"
        return content
    return "-1"


def exception(param):
    messagebox.showwarning("Предупреждение", param)


def choose_file():
    global filename
    try:
        filetype = (("Текстовый файл", '*.txt'), ("All files", '*.*'))
        filename = fd.askopenfilename(title="Открыть файл", initialdir="/", filetypes=filetype)
        if filename == "":
            raise Exception("Файл не выбран")
    except Exception as e:
        exception(e)
        return False
    return True


def send_file():
    global hash_text
    global isFile
    text_message = read_file()
    if text_message != "-1":
        print(text_message)
        h_text = hashlib.md5(text_message.encode())
        hash_text = h_text.digest()
        box = KSA(K)
        cipher_text_message = PRGA(text_message, box)
        client.send(cipher_text_message.encode())
        isFile = True
    else:
        messagebox.showwarning("Что - то пошло не так...")


def create_chat():
    global window
    global List
    global font
    for i in List:
        i.destroy()
        window.update()
    List.clear()
    window.title('Чат с сервером')
    window.geometry('400x500')
    window.resizable(0, 0)
    window['bg'] = "#f2e3f4"
    text = Text(width=25, height=12, font=font)
    text.pack(side=TOP)
    List.append(text)
    scroll = Scrollbar(command=text.yview)
    scroll.pack(side=LEFT, fill=Y)
    text.config(yscrollcommand=scroll.set)
    entry = Entry(window, font=font)
    entry.place(x=35, y=350)
    List.append(entry)
    button = Button(window, text="Отправить", font=font, command=send_message)
    button.place(x=30, y=420)
    List.append(button)
    button2 = Button(window, text="Отправить файл", font=font, command=send_file)
    button2.place(x=180, y=420)
    List.append(button2)


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


def send_message():
    global count
    message = List[1].get()
    box = KSA(K)
    cipher_message = PRGA(message, box)
    List[0].insert(float(count), "Client: " + message + "\n" + "Client (encrypted): " + cipher_message + "\n")
    count += 2
    client.send(cipher_message.encode())


def listen_server(user):
    global isFile
    global count
    global hash_text
    while True:
        data = user.recv(2048).decode("utf-8")
        if not isFile:
            box = KSA(K)
            decrypted_message = PRGA(data, box)
            List[0].insert(float(count), "Server (decrypted): " + decrypted_message + "\n" + "Server: " + data + "\n")
            count += 2
        else:
            separator = data.find(" ")
            e = int(data[:separator])
            n = int(data[separator + 1:])
            print(struct.unpack('<hi', hash_text))
            hash_text = str(pow(int.from_bytes(hash_text, 'big'), e, n))
            client.send(hash_text.encode())
            isFile = False


def clicked():
    global K
    # получаем имя пользователя и пароль
    username = username_entry.get()
    password = password_entry.get()
    hash_pass = hashlib.md5(password.encode())
    hash_password = hash_pass.hexdigest()
    data = username

    # отправляем логин
    client.send(data.encode())

    # получаем метку t
    t = client.recv(1024).decode("utf8")
    data = hash_password + t
    h = hashlib.md5(data.encode())
    hash = h.hexdigest()

    # отправляем password + t
    client.send(hash.encode())
    answ = client.recv(1024).decode("utf8")

    # ответ сервера
    messagebox.showinfo("Info", answ)

    # Получаем g, p, A
    g = int(client.recv(2048).decode("utf-8"))
    client.send("ok".encode("utf-8"))
    p = int(client.recv(2048).decode("utf-8"))
    client.send("ok".encode("utf-8"))
    A = int(client.recv(2048).decode("utf-8"))
    client.send("ok".encode("utf-8"))
    messagebox.showinfo("Client receive", f"g = {g}, p = {p}, A = {A}")

    # Генерим b, вычисляем B, отправляем
    b = random.getrandbits(64)
    B = pow(g, b, p)
    client.send(str(B).encode("utf-8"))

    # Генерируем K
    K = str(pow(A, b, p))
    print(K)

    # Чат
    create_chat()
    thread = Thread(target=listen_server, args=(client,))
    thread.start()

    # client.close()


# Виджеты окна регистрации

List = []

font = ("Century Gothic", 16)

username_label = Label(window, text='Логин', font=font)
username_label.pack()
List.append(username_label)

username_entry = Entry(window, font=font)
username_entry.pack()
List.append(username_entry)

password_label = Label(window, text='Пароль', font=font)
password_label.pack()
List.append(password_label)

password_entry = Entry(window, font=font)
password_entry.pack()
List.append(password_entry)

send_button = Button(window, text='Авторизация', command=clicked, font=font)
send_button.place(x=65, y=140)
List.append(send_button)

window.mainloop()
