import ftplib
import tkinter
import tkinter.font
import time
from tkinter import *
from tkinter.ttk import *
import exrex
from cryptography.fernet import Fernet
import socket
from requests import get
import requests
import re
import threading
import os
# important.py: including ftp address, ID, PW, Port, Encryption Key, Email, Email_Password
import important

"""
==============important.py===============
url = 'Your FTP address'
id = 'Your FTP ID'
pw = 'Your FTP password'
port = 'Your FTP port number'
encryptKey = b'Fernet encryption key'
mailID = 'Your Email to send codes for new people'
mailPW = 'Your Email password'
smtpServer = 'smtp.XXXX.com'
==========================================
"""

url = important.url
id = important.id
pw = important.pw
port = important.port
rootFile = '/HDD1/chat'

session = ftplib.FTP()
session.connect(url, port=port, timeout=3600)
session.login(id, pw)
session.encoding = 'EUC-KR'
session.cwd(rootFile)
chattingRoomStart = True

chatLogFile = 'ChatLog.txt'
infoFile = 'InfoFile.txt'
friendsListFile = 'FriendsListFile.txt'
onlyNameFile = 'OnlyNameFile.txt'
localFolder = 'localChatFiles/'

retry = 0
writingMessageNum = 0
messageNum = 0
newMessageCame = False
unreadMessages = 0
nextUnreadMessages = 0
changeDetect = 0
beforeLastMessageNum = None
lastMessageNum = None
successRead = False
mainDelayTime = 10000
delayTime = 100
shortDelayTime = 10
downFailTime = 0
madeAccount = False
registered = False
findingFriends = False
threadRunning = False
accessing = False
firstDir = ''
messageSent = False
sentMessage = ''


class SimpleEnDecrypt:
    def __init__(self, key=None):
        if key is None:  # 키가 없다면
            key = important.encryptKey  # 키43개
        self.key = key
        self.f = Fernet(self.key)
        # print(key)

    def encrypt(self, data, is_out_string=True):
        try:
            ou = self.f.encrypt(data.encode('cp949'))  # 인코딩 후 암호화
            if is_out_string is True:
                return ou.decode('cp949')  # 출력이 문자열이면 디코딩 후 반환
            else:
                return ou
        except:
            # print('encrypt fail')
            pass

    def decrypt(self, data, is_out_string=True):
        try:
            ou = self.f.decrypt(data.encode('cp949'))  # 인코딩 후 복호화
            if is_out_string is True:
                return ou.decode('cp949')  # 출력이 문자열이면 디코딩 후 반환
            else:
                return ou
        except:
            # print('decrypt fail')
            return data


simpleED = SimpleEnDecrypt()


def reconnect(directory):
    try:
        session.connect(url, port=port)
        session.login(id, pw)
        session.encoding = 'EUC-KR'
        session.cwd(directory)
        append("Connected")
    except:
        append("Reconnecting...")
        pass


def info():
    url = 'http://ip-api.com/json'
    data = requests.get(url)
    res = data.json()
    country = res["countryCode"]
    externalIp = get("https://api.ipify.org").text
    return f'Device:{socket.gethostname()} Internal:{socket.gethostbyname(socket.gethostname())} External:{externalIp}'


def eraseAll():
    global chattingRoomStart, nextUnreadMessages, writingMessageNum, messageNum, newMessageCame, unreadMessages, changeDetect, ChattingRoom_frame
    eraseLocal(chattingFileLocation)
    upload(chattingFileLocation)
    chattingRoomStart = True
    nextUnreadMessages = 0
    writingMessageNum = 0
    messageNum = 0
    newMessageCame = False
    unreadMessages = 0
    changeDetect = 0
    modifyFriendList(currentChattingFriend, 0)
    conversation_text.configure(state='normal')
    conversation_text.delete("0", "end")
    conversation_text.configure(state='disabled')


def download(direct, alert=None):
    global downFailTime, firstDir
    try:
        print(f'다운 받는 곳 {session.pwd()}, {direct}')
        firstDir = session.pwd()
        with open('local' + direct, 'wb') as f:
            session.retrbinary('RETR ' + direct, f.write)
            print('down ok')
    except:
        if alert is False:
            return False
        downFailTime += 1
        print(downFailTime)

        print('in def download: Download Failed')
    if downFailTime > 10:
        if alert is False:
            return
        reconnect(firstDir)
        downFailTime = 0
        print('reconnecting')


def read(fileName):
    global messageNum, newMessageCame, unreadMessages, unread, lastMessageNum, messageSent,sentMessage, \
        nextUnreadMessages, chattingRoomStart, writingMessageNum, changeDetect, Name, chatting, beforeLastMessageNum, successRead
    messageNum = 0  # 이거 있어야만 다른 방 들어갈 때 메세지 수 안섞임
    with open('local' + fileName, 'r', encoding='cp949') as f:
        readMessage = f.readlines()
        if readMessage:
            successRead = True
        else:
            print('Noting ro read\n')
            if not chattingRoomStart:
                print("Read Fail!!\n")
                pass
            successRead = False
            return
        for newCheck in readMessage:
            newCheck = simpleED.decrypt(newCheck)
            maxLength = 20
            plusLength = 20
            startLength = 0
            AllRex = r'\[(.*)\] Date:(.*) Time:(.*) Name: (.*) Message: (.*)'
            try:
                RAll = re.compile(AllRex)
                MAll = RAll.search(newCheck)
                messageNum = int(MAll.group(1))  # 들어온 메시지의 숫자
                Date = MAll.group(2)
                Time = MAll.group(3)
                Name = MAll.group(4)
                if infoName == Name:
                    Name = '나'
                Message = MAll.group(5)
            except:
                eraseAll()
                append('Initialized by problems in decryption')
                return
            # 방 처음에 들어왔을 때 서버 안에 있는 메세지 출력
            if chattingRoomStart:
                repeatTime = len(Message) // maxLength + 1
                # 리스트박스로 해서 글자 길어지면 자동으로 안내려가서 20줄 넘으면 수동으로 또 올려줘야함
                blank = ''
                for i in range(len(f'{Time}] : ') + (len(f'{Name}') + 1) * 2):
                    blank += ' '
                for i in range(repeatTime):
                    if i == 0:
                        readingText = f'[{Time}] {Name}: {Message[startLength:maxLength]}'
                    else:
                        readingText = f'{blank}{Message[startLength:maxLength]}'
                    startLength += plusLength
                    maxLength += plusLength
                    if not readMessage:
                        messageNum = 0
                    append(readingText)
                    writingMessageNum = messageNum
        lastMessageNum = messageNum
        if chattingRoomStart:
            beforeLastMessageNum = lastMessageNum
        if not chattingRoomStart and beforeLastMessageNum != lastMessageNum:
            newMessageCame = True
        elif not chattingRoomStart and beforeLastMessageNum == lastMessageNum:
            newMessageCame = False
        if newMessageCame is True and readMessage and not chattingRoomStart:
            for newCheck in readMessage:
                newCheck = simpleED.decrypt(newCheck)
                maxLength = 20
                plusLength = 20
                startLength = 0
                AllRex = r'\[(.*)\] Date:(.*) Time:(.*) Name: (.*) Message: (.*)'
                RAll = re.compile(AllRex)
                MAll = RAll.search(newCheck)
                messageNum = int(MAll.group(1))
                Date = MAll.group(2)
                Time = MAll.group(3)
                Name = MAll.group(4)
                if infoName == Name:
                    Name = '나'
                Message = MAll.group(5)
                if messageNum > beforeLastMessageNum:
                    # 리스트박스로 해서 글자 길어지면 자동으로 안내려가서 20줄 넘으면 수동으로 또 올려줘야함
                    repeatTime = len(Message) // maxLength + 1
                    blank = ''
                    for i in range(len(f'{Time}] : ') + (len(f'{Name}') + 1) * 2):
                        blank += ' '
                    for i in range(repeatTime):
                        if i == 0:
                            readingText = f'[{Time}] {Name}: {Message[startLength:maxLength]}'
                        else:
                            readingText = f'{blank}{Message[startLength:maxLength]}'
                        print(f'{Message}  {Message[startLength:maxLength]}')

                        startLength += plusLength
                        maxLength += plusLength
                        append(readingText)
            beforeLastMessageNum = lastMessageNum
            changeDetect = nextUnreadMessages
        chattingRoomStart = False

        if messageSent:
            print(sentMessage, newCheck)
            if sentMessage != newCheck:
                print("충돌로 인해 재전송")
                print(f'내가 보낸 메시지: {sentMessage}')
                print(f'상대가 보낸 메시지: {newCheck}')

                Write(chattingFileLocation, Message=sentMessage)
                sentMessage = ''
            messageSent = False


def writeDate():
    global now
    now = time.gmtime(time.time())
    return '%02d.%02d.%02d' % (now.tm_year, now.tm_mon, now.tm_mday)


def writeTime():
    global now
    now = time.gmtime(time.time())
    kor_hour = (now.tm_hour + 9) % 24
    return '%02d:%02d' % (kor_hour, now.tm_min)


def eraseLocal(direct):
    with open('local' + direct, 'w', encoding='cp949') as f:
        f.close()


def Write(fileName, Message=None):
    global lastMessageNum, messageNum, unread, sentMessage, messageSent
    with open('local' + fileName, 'a', encoding='cp949') as f:
        message = ent.get()
        if Message:
            message = Message
        if message:
            lastMessageNum = messageNum + 1
            ent.delete(0, END)
            sentence = f'[{lastMessageNum}] Date:{writeDate()} Time:{writeTime()} Name: {infoName} Message: {str(message)}'
            sentMessage = sentence
            sentence = simpleED.encrypt(sentence)  # 암호화
            f.write(sentence + '\n')
            messageSent = True


def upload(fileName):
    with open('local' + fileName, 'rb') as f:
        session.storbinary('STOR ' + fileName, f)
        # print(session.pwd()) 한글 루트이면 오류남


def send(event=None):
    global accessing
    if not successRead and chattingRoomStart or successRead and not chattingRoomStart:
        Write(chattingFileLocation)
        upload(chattingFileLocation)
        # 보낼 때는 after 안사용하고 바로 보냄. 그래야 delay 없이 바로 뜸
        download(chattingFileLocation)
        read(chattingFileLocation)
        Window.after(delayTime, accessingFalse)


def accessingFalse(event=None):
    global accessing
    accessing = False


def sendThread(event=None):
    global accessing, retry
    if location == 'Chatting':
        if accessing is False:
            accessing = True
            threading.Thread(target=send).start()
            retry = 0
            return
        if accessing and retry < 50 and ent.get() != '':
            print(f"retry {retry}")
            retry += 1
            Window.after(10, sendThread)
        else:
            retry = 0


def append(chatting):
    try:
        conversation_text.configure(state='normal')
        conversation_text.insert('end', chatting)
        conversation_text.configure(state='disabled')
        conversation_text.yview_moveto(1)
    except:
        pass


def appendMain(i, friends, friendMail, messageCame):
    friend_list.insert(i, f'{friends} {friendMail} {messageCame}')
    friend_list.yview_moveto(1)


def rgb_hack(rgb):
    return "#%02x%02x%02x" % rgb


def nothing(event=None):
    # 키바인드 초기화를 위해 만든 것
    pass


def downAndRead():
    global accessing
    download(chattingFileLocation)
    read(chattingFileLocation)
    print('chatting')
    Window.after(delayTime, accessingFalse)


def chattingLoop():
    global accessing
    if location == 'Chatting':
        if accessing is False:
            accessing = True
            print(f'채팅루프 {chattingFileLocation}')
            threading.Thread(target=downAndRead).start()
        Window.after(delayTime, chattingLoop)


def mainLoop():
    if location == 'Main':
        threading.Thread(target=numOfMessageCame).start()
        Window.after(mainDelayTime, mainLoop)


# 여기가 시작임
location = ''
Window = Tk()
Window.title('FTP Talk')
Window.geometry("380x563+800+300")
# Window.wm_attributes('-transparentcolor', rgb_hack((150, 150, 150)))
Window.resizable(False, False)
# Window.overrideredirect(1)
font = tkinter.font.Font(family="맑은 고딕", size=10)
noticeFont = tkinter.font.Font(family="Arial", size=15, weight='bold')

Window.iconbitmap("2.ico")
# Window.iconphoto("2.ico")


LogIn_frame = Frame(Window)
ChattingRoom_frame = Frame(Window)
Register_frame = Frame(Window)
Main_frame = Frame(Window)


def goChatting(event=None):
    global chattingRoomStart, ChattingRoom_frame, conversation_text, ent, location
    location = 'Chatting'
    Window.after(shortDelayTime, chattingLoop)
    Window.title(f'Chat with: {currentChattingFriend}')
    print('chatting')
    chattingRoomStart = True
    LogIn_frame.destroy()
    Main_frame.destroy()
    ChattingRoom_frame = Frame(Window)
    ChattingRoom_frame.pack()
    backButton = Button(ChattingRoom_frame, text="Back", command=chattingToMain, takefocus=False)
    backButton.grid(column=0, row=0, sticky=W + S + N + E)
    initButton = Button(ChattingRoom_frame, text="Init", command=eraseAll, takefocus=False)
    initButton.grid(column=1, row=0, sticky=W + S + N + E)
    menuButton = Button(ChattingRoom_frame, text="Refresh", command=refreshChatting, takefocus=False)
    menuButton.grid(column=2, row=0, sticky=W + S + N + E)
    conversation_text = Listbox(ChattingRoom_frame, height=28, width=52, relief=FLAT, font=font,
                                disabledforeground=rgb_hack((0, 0, 0)))
    conversation_text.configure(state='disabled')
    conversation_text.grid(column=0, row=1, columnspan=3, sticky=W + S + N)
    ent = tkinter.Entry(ChattingRoom_frame, width=40, insertwidth=1, bg=rgb_hack((220, 220, 220)), font=font)
    ent.grid(column=0, row=2, columnspan=3, sticky=W + S + N)
    button = Button(ChattingRoom_frame, text="Send", command=sendThread, takefocus=False)
    button.grid(column=2, row=2, sticky=E + S + N)
    Window.bind("<Return>", sendThread)
    Window.bind("<Escape>", chattingToMain)
    Window.bind('<Double-1>', nothing)


def chattingToMain(event=None):
    currentDir = session.pwd()
    print(f'message num in current chatting {messageNum}')
    modifyFriendList(currentChattingFriend, lastMessageNum)
    session.cwd(currentDir)
    goMain()


def refreshChatting(event=None):
    ChattingRoom_frame.destroy()
    goChatting()


def goLogin(event=None):
    global location, ID_entry, PW_entry, LogIn_frame, Alert_label, findingFriends, writingMessageNum, messageNum, newMessageCame, unreadMessages, nextUnreadMessages \
        , changeDetect, beforeLastMessageNum, lastMessageNum, successRead, mainDelayTime, delayTime, shortDelayTime, downFailTime, madeAccount, registered, accessing, remember_button
    Window.title('FTP Talk')
    writingMessageNum = 0
    messageNum = 0
    newMessageCame = False
    unreadMessages = 0
    nextUnreadMessages = 0
    changeDetect = 0
    beforeLastMessageNum = None
    lastMessageNum = None
    successRead = False
    mainDelayTime = 10000
    delayTime = 100
    shortDelayTime = 10
    downFailTime = 0
    madeAccount = False
    registered = False
    findingFriends = False
    accessing = False
    findingFriends = False

    session.cwd(rootFile)  # chat
    location = 'Login'
    print('Login')
    ChattingRoom_frame.destroy()
    Register_frame.destroy()
    Main_frame.destroy()
    LogIn_frame = Frame(Window)
    LogIn_frame.pack(pady=50)
    Alert_label = Label(LogIn_frame, text='', anchor='s', font=noticeFont)
    Alert_label.pack()
    ID_label = Label(LogIn_frame, text='E-Mail')
    ID_label.pack()
    ID_entry = tkinter.Entry(LogIn_frame, width=40, insertwidth=1, font=font)
    ID_entry.pack()
    PW_label = Label(LogIn_frame, text='Password')
    PW_label.pack()
    PW_entry = tkinter.Entry(LogIn_frame, width=40, insertwidth=1, font=font, show='*')
    PW_entry.pack()
    remember_button = Checkbutton(LogIn_frame, text="Remember E-Mail")
    remember_button.pack(pady=10)
    remember_button.state(['!alternate'])
    try:
        rememberedID = directlyRead('rememberedID.txt')
        rememberedID = simpleED.decrypt(rememberedID)
        ID_entry.insert(0, rememberedID)
        remember_button.state(['selected'])
    except:
        remember_button.state(['!alternate'])
    Enter_button = Button(LogIn_frame, text="Enter", command=logIn, takefocus=False, width=20)
    Enter_button.pack(pady=10)
    or_label = Label(LogIn_frame, text='or')
    or_label.pack()
    Reg_button = Button(LogIn_frame, text="Register", command=goRegister, takefocus=False, width=10)
    Reg_button.pack(pady=10)
    Window.bind("<Return>", logIn)
    Window.bind("<Escape>", nothing)
    Window.bind('<Double-1>', nothing)


def goRegister(event=None):
    global Register_frame, location, Mail_entry, Name_entry, PW_entry, PWAgain_entry, notice_label, myAssortedName, Mail_label, Certify_entry
    session.cwd(rootFile)
    location = 'Register'
    print('in login')
    Window.title(f'Welcome')
    LogIn_frame.destroy()
    Register_frame = Frame(Window)
    Register_frame.pack(pady=50)
    Mail_label = Label(Register_frame, text='E-Mail', anchor='s')
    Mail_label.pack()
    Mail_entry = tkinter.Entry(Register_frame, width=40, insertwidth=1, font=font)
    Mail_entry.pack(pady=10)
    Certify_button = Button(Register_frame, text="Certify", command=mailCertify, takefocus=False, width=10)
    Certify_button.pack()
    Certify_entry = tkinter.Entry(Register_frame, width=20, insertwidth=1, font=font)
    Certify_entry.pack(pady=5)
    Submit_button = Button(Register_frame, text="Submit", command=submit, takefocus=False, width=10)
    Submit_button.pack(pady=5)
    Name_label = Label(Register_frame, text='NAME', anchor='s')
    Name_label.pack()
    Name_entry = tkinter.Entry(Register_frame, width=40, insertwidth=1, font=font)
    Name_entry.pack(pady=10)
    PW_label = Label(Register_frame, text='PW', anchor='s')
    PW_label.pack()
    PW_entry = tkinter.Entry(Register_frame, width=40, insertwidth=1, font=font, show='*')
    PW_entry.pack(pady=10)
    PWAgain_label = Label(Register_frame, text='PW again', anchor='s')
    PWAgain_label.pack()
    PWAgain_entry = tkinter.Entry(Register_frame, width=40, insertwidth=1, font=font, show='*')
    PWAgain_entry.pack(pady=10)
    notice_label = Label(Register_frame, text='', anchor='s', font=noticeFont)
    notice_label.pack()
    Enter_button = Button(Register_frame, text="Enter", command=register, takefocus=False, width=20)
    Enter_button.pack(pady=20)
    Back_button = Button(Register_frame, text="Back", command=goLogin, takefocus=False, width=10)
    Back_button.pack(pady=20)
    Window.bind("<Return>", register)
    Window.bind("<Escape>", goLogin)
    Window.bind('<Double-1>', nothing)


def goMain(event=None):
    session.cwd(rootFile)
    global location, Main_frame, friend_list, FriendFind_ent, FriendFind_label, findingFriends, refresh_button, threadRunning, addFriend_button, logout_button, FriendFind_button, join_button, Delete_button, Every_button
    location = 'Main'
    print('in main')
    Window.title(f'User: {infoName}')
    refresh()
    LogIn_frame.destroy()
    ChattingRoom_frame.destroy()
    Main_frame = Frame(Window)
    Main_frame.pack()
    logout_button = Button(Main_frame, text="Logout", command=goLogin, takefocus=False, state=DISABLED)
    logout_button.grid(column=0, row=0, sticky=W + S + N + E)
    addFriend_button = Button(Main_frame, text="Add friend", command=switch, takefocus=False, state=DISABLED)
    addFriend_button.grid(column=1, row=0, sticky=W + S + N + E)
    refresh_button = Button(Main_frame, text="Refresh", command=refresh, takefocus=False, state=DISABLED)
    refresh_button.grid(column=2, row=0, sticky=W + S + N + E)
    if findingFriends:
        plusRow = 2
        plusHeight = -3
        FriendFind_label = Label(Main_frame, text='Search by E-Mail', anchor='s', font=font)
        FriendFind_label.grid(column=0, row=1, columnspan=3, sticky=W + E + S + N, pady=6)
        FriendFind_ent = tkinter.Entry(Main_frame, width=40, insertwidth=1, bg=rgb_hack((220, 220, 220)), font=font)
        FriendFind_ent.grid(column=0, row=2, columnspan=3, sticky=W + S + N)
        FriendFind_button = Button(Main_frame, text="Add", command=findFriend, takefocus=False, state=DISABLED)
        FriendFind_button.grid(column=2, row=2, sticky=E + S + N)
    else:
        plusRow = 0
        plusHeight = 0
    friend_list = Listbox(Main_frame, height=28 + plusHeight, width=52, relief=FLAT, font=font,
                          selectbackground=rgb_hack((50, 50, 50)), activestyle=NONE)
    friend_list.grid(column=0, row=1 + plusRow, columnspan=3, sticky=W + S + N)
    join_button = Button(Main_frame, text="Join", command=joinOrMakeRoom, takefocus=False, state=DISABLED)
    join_button.grid(column=0, row=2 + plusRow, sticky=W + S + N + E)
    Delete_button = Button(Main_frame, text="Delete", command=deleteFriend, takefocus=False, state=DISABLED)
    Delete_button.grid(column=1, row=2 + plusRow, sticky=W + S + N + E)
    Every_button = Button(Main_frame, text="Every Chat", command=everyChat, takefocus=False, state=DISABLED)
    Every_button.grid(column=2, row=2 + plusRow, sticky=W + S + N + E)
    if findingFriends:
        Window.bind("<Return>", findFriend)
    else:
        Window.bind("<Return>", joinOrMakeRoom)
    Window.bind('<Double-1>', nothing)
    Window.bind("<Escape>", nothing)


def refresh(event=None):
    global threadRunning, refresh_button, addFriend_button, logout_button, FriendFind_button, join_button, Delete_button, Every_button
    try:
        logout_button['state'] = DISABLED
        addFriend_button['state'] = DISABLED
        refresh_button['state'] = DISABLED
        join_button['state'] = DISABLED
        Delete_button['state'] = DISABLED
        Every_button['state'] = DISABLED
        Window.bind('<Double-1>', nothing)
        Window.bind("<Escape>", nothing)
        # 이거 마지막에 있어야 함
        FriendFind_button['state'] = DISABLED
    except:
        pass
    if threadRunning is False:
        threadRunning = True
        threading.Thread(target=numOfMessageCame).start()


def threadFalse(event=None):
    global threadRunning, refresh_button, addFriend_button, logout_button, FriendFind_button, join_button, Delete_button, Every_button
    try:
        threadRunning = False
        logout_button['state'] = NORMAL
        addFriend_button['state'] = NORMAL
        refresh_button['state'] = NORMAL
        join_button['state'] = NORMAL
        Delete_button['state'] = NORMAL
        Every_button['state'] = NORMAL
        Window.bind('<Double-1>', joinOrMakeRoom)
        Window.bind("<Escape>", goLogin)
        # 이거 마지막에 있어야 함
        FriendFind_button['state'] = NORMAL
    except:
        pass


def switch(event=None):
    global findingFriends
    Main_frame.destroy()
    if findingFriends:
        findingFriends = False
    else:
        findingFriends = True
    goMain()


def findFriend(event=None):
    friendMail = FriendFind_ent.get()
    # print(f'{logID},{friendMail}')
    if logID == friendMail:
        FriendFind_label['text'] = "It's your E-Mail..."
        return
    # 친구 파일에서 이름 가져와서 로컬에 저장하는 파일이라서 나중에 내 이름이랑 섞일 수 있어서 삭제함
    try:
        session.cwd(f'{rootFile}/{friendMail}')
    except:
        FriendFind_label['text'] = 'Not Exist.. Try again'
        return
    download(onlyNameFile)
    friendName = directlyRead(onlyNameFile)
    friendName = friendName.strip()
    eraseLocal(onlyNameFile)
    friendInfo = f'{friendName} {friendMail}'
    FriendFind_ent.delete(END)
    print("친구찾기 ")
    session.cwd(f'{rootFile}/{logID}')
    download(friendsListFile)
    with open('local' + friendsListFile, 'r', encoding='cp949') as f:
        readMessage = f.readlines()
        print(f'readMessage: {readMessage}')
        if readMessage:
            for friends in readMessage:
                friends = friends.strip()
                friends = simpleED.decrypt(friends)
                print(f'friend: {friends}, friendInfo: {friendInfo}')
                if friendInfo in friends:
                    FriendFind_label['text'] = 'Already exist'
                    return
        # print('친추')
        try:
            friendName = getFriendName(friendMail)
            addMyNameToFriendsFriendList(friendMail)
            addFriendToMyFriendList(friendName, friendMail)
            appendMain(END, friendName, friendMail, [0])
            FriendFind_ent.delete(0, END)
            FriendFind_label['text'] = 'Added to my friends'
        except:
            FriendFind_label['text'] = 'Some problems'
            return


def addFriendToMyFriendList(friendName, friendMail):
    # 내 친구목록에 추가해서 업로드
    session.cwd(f'{rootFile}/{logID}')
    download(friendsListFile)
    directlyModifyFile(friendsListFile, f'{friendName} {friendMail} [0]')
    print(f'내 친구리스트에 추가한 것 {friendName} {friendMail} {lastMessageNum}')
    upload(friendsListFile)
    session.cwd(rootFile)


def addMyNameToFriendsFriendList(friendMail):
    # 추가한 친구의 친구목록을 불러와서 수정후 업로드
    session.cwd(f'{rootFile}/{friendMail}')
    download(friendsListFile)
    directlyModifyFile(friendsListFile, f'{myName} {logID} [0]')
    print(f'친구의 친구리스트에 추가한 것 {myName} {logID} 0')
    upload(friendsListFile)
    session.cwd(rootFile)


def deleteFriend(event=None):
    selectedFriend = friend_list.get(friend_list.curselection())
    AllRex = r'(.*) (.*) \[(.*)\]$'  # 가입할때 빈칸 없게 조심해야 함
    RAll = re.compile(AllRex)
    MAll = RAll.search(selectedFriend)
    friendName = MAll.group(1)
    friendMail = MAll.group(2)
    modifyFriendList(friendMail, 0, deleteAll=True)
    modifyFriendsFriendList(friendMail, 0, deleteAll=True)
    refresh()


def getFriendName(friendMail):
    session.cwd(f'{rootFile}/{friendMail}')
    download(onlyNameFile)
    friendName = directlyRead(onlyNameFile)
    friendName = friendName.strip()
    session.cwd(rootFile)
    return friendName


def modifyFriendsFriendList(friendMail, currentNum, deleteAll=False):
    curDir = session.pwd()
    if logID != '':
        session.cwd(f'{rootFile}/{friendMail}')
        download(friendsListFile)
        with open('local' + friendsListFile, 'r', encoding='cp949') as f:
            # print('opened')
            friendsList = f.readlines()
            allSentence = ''
            if friendsList:
                print("friendlist 있음")
                for friendInfo in friendsList:
                    friendInfo = simpleED.decrypt(friendInfo)
                    if logID in friendInfo:
                        AllRex = r'(.*) (.*) \[(.*)\]$'
                        RAll = re.compile(AllRex)
                        MAll = RAll.search(friendInfo)
                        # print(f'friend info: {friendInfo}')
                        name = MAll.group(1)
                        mail = MAll.group(2)
                        if not currentNum:
                            currentNum = 0
                        if deleteAll is False:
                            info = simpleED.encrypt(f'{name} {mail} [{currentNum}]')
                            allSentence += info + '\n'
                    else:
                        info = simpleED.encrypt(f'{friendInfo}')
                        allSentence += info + '\n'
                with open('local' + friendsListFile, 'w', encoding='cp949') as wf:
                    wf.write(allSentence)
            upload(friendsListFile)
    session.cwd(curDir)


def modifyFriendList(friendMail, currentNum, deleteAll=False):
    curDir = session.pwd()
    if friendMail != '':
        session.cwd(f'{rootFile}/{logID}')
        download(friendsListFile)
        with open('local' + friendsListFile, 'r', encoding='cp949') as f:
            # print('opened')
            friendsList = f.readlines()
            allSentence = ''
            if friendsList:
                print("friendlist 있음")
                for friendInfo in friendsList:
                    friendInfo = simpleED.decrypt(friendInfo)
                    if f'{friendMail} ' in friendInfo:  # friendName 오른쪽에 빈칸 있어야 함
                        print(f'this {friendMail} friendinfo: {friendInfo}')
                        AllRex = r'(.*) (.*) \[(.*)\]$'
                        RAll = re.compile(AllRex)
                        MAll = RAll.search(friendInfo)
                        print(f'friend info: {friendInfo}')
                        name = MAll.group(1)
                        mail = MAll.group(2)
                        if not currentNum:
                            currentNum = 0
                        if deleteAll is False:
                            info = simpleED.encrypt(f'{name} {mail} [{currentNum}]')
                            allSentence += info + '\n'
                    else:
                        info = simpleED.encrypt(f'{friendInfo}')
                        allSentence += info + '\n'
                    with open('local' + friendsListFile, 'w', encoding='cp949') as wf:
                        wf.write(allSentence)
            print(f'{friendMail}와의 대화 개수 업로드{currentNum}')
            upload(friendsListFile)
    session.cwd(curDir)


def numOfMessageCame(event=None):
    global messageCame
    session.cwd(f'{rootFile}/{logID}')
    download(friendsListFile)
    with open('local' + friendsListFile, 'r', encoding='cp949') as f:
        friendsList = f.readlines()
        if friendsList:
            i = 0
            for friendNameMail in friendsList:
                friendNameMail = simpleED.decrypt(friendNameMail)
                print('친구이름메일' + friendNameMail)
                AllRex = r'(.*) (.*) \[(.*)\]'
                RAll = re.compile(AllRex)
                MAll = RAll.search(friendNameMail)
                friendName = MAll.group(1)
                friendMail = MAll.group(2)
                lastChatNumber = MAll.group(3)
                messageCame1 = messageLengthCheck(f'{rootFile}/{logID}', f'{friendMail}.txt') - int(lastChatNumber)
                messageCame2 = messageLengthCheck(f'{rootFile}/{friendMail}', f'{logID}.txt') - int(lastChatNumber)
                if messageCame1 >= messageCame2:
                    messageCame = messageCame1
                    print(f'{friendMail} 내 폴더에 상대와의 대화가 있음 {messageCame1}개')
                else:
                    messageCame = messageCame2
                    # print(f'{friendMail} 상대의 폴더에 나와의 대화가 있음 {messageCame2}개')
                if messageCame < 0:
                    lastChatNumber = 0
                    # print(f'{messageCame}')
                    messageCame = messageLengthCheck(f'{rootFile}/{logID}', f'{friendMail}.txt') - int(lastChatNumber)
                print(f'came: {messageCame} = LengthCheck: {messageLengthCheck(f"{rootFile}/{logID}", f"{friendMail}.txt") + messageLengthCheck(f"{rootFile}/{friendMail}", f"{logID}.txt")} - last:{lastChatNumber}")')
                # print(i)
                friend_list.delete(i)
                appendMain(i, friendName, friendMail, f'[{messageCame}]')
                i += 1
            friend_list.delete(i, END)
        else:
            friend_list.delete(0, END)
    Window.after(10, threadFalse)


def messageLengthCheck(directory, fileName):
    session.cwd(directory)
    if download(fileName, alert=False) is False:
        # print(f'{directory}  {fileName} 여기는 파일이 없음 길이 0 반환')
        return 0
    with open('local' + fileName, 'r', encoding='cp949') as f:
        readMessage = f.readlines()
        if not readMessage:
            return 0
        for newCheck in readMessage:
            newCheck = simpleED.decrypt(newCheck)
            AllRex = r'\[(.*)\] Date:(.*) Time:(.*) Name: (.*) Message: (.*)'
            try:
                RAll = re.compile(AllRex)
                MAll = RAll.search(newCheck)
                messageNum = int(MAll.group(1))  # 들어온 메시지의 숫자
            except:
                eraseAll()
                append('Initialized by problems in decryption in length checking')
        finalMessageNum = messageNum
        print(f'마지막으로 보낸 메시지 숫자:{finalMessageNum}')
        return finalMessageNum


def directlyRead(fileName):
    with open('local' + fileName, 'r', encoding='cp949') as f:
        readMessage = f.readlines()
        if readMessage:
            for newCheck in readMessage:
                print(newCheck)
                newCheck = simpleED.decrypt(newCheck)
                f.close()
                return newCheck
        else:
            print('nothing read')
            pass


def directlyWrite(fileName, sentence):
    with open('local' + fileName, 'w', encoding='cp949') as f:
        if sentence:
            sentence = simpleED.encrypt(sentence)
            f.write(sentence)


def directlyModifyFile(fileName, sentence):
    with open('local' + fileName, 'a', encoding='cp949') as f:
        if sentence:
            sentence = simpleED.encrypt(sentence)
            f.write(sentence + '\n')


def joinOrMakeRoom(event=None):
    global chattingFileLocation, lastChatNumber, currentChattingFriend
    selectedFriend = friend_list.get(friend_list.curselection())
    AllRex = r'(.*) (.*) \[(.*)\]$'  # 가입할때 빈칸 없게 조심해야 함
    RAll = re.compile(AllRex)
    MAll = RAll.search(selectedFriend)
    friendName = MAll.group(1)
    currentChattingFriend = friendName
    friendMail = MAll.group(2)
    lastChatNumber = MAll.group(3)
    print(f'/HDD1/chat/{friendMail}')
    session.cwd(f'{rootFile}/{friendMail}')  # 친구의 폴더로 들어가서 먼저 확인
    if download(f'{logID}.txt', alert=False) is False:
        session.cwd(f'{rootFile}/{logID}')  # 내 폴더로 들어가서 확인
        if download(f'{friendMail}.txt', alert=False) is False:
            print(logID)
            print(f'{friendMail}.txt')
            print('상대방에게 채팅방이 없어 내 폴더에서 생성')
            session.cwd(f'{rootFile}/{logID}')
            directlyWrite(f'{friendMail}.txt', None)
            upload(f'{friendMail}.txt')
            chattingFileLocation = f'{friendMail}.txt'
            print(f'여기서 채팅방 생성 {rootFile}/{logID}')
        else:
            print('나에게 방 존재')
            print(f'내 방으로 들어감 {rootFile}/{logID}')
            chattingFileLocation = f'{friendMail}.txt'
    else:
        print('상대방에게 방 존재')
        print(f'상대방한테 들어감{rootFile}/{friendMail}')
        chattingFileLocation = f'{logID}.txt'
    print(f'{chattingFileLocation}')
    goChatting()


def everyChat(event=None):
    global chattingFileLocation, currentChattingFriend
    session.cwd(rootFile)
    currentChattingFriend = 'Everyone'
    chattingFileLocation = f'EveryChat.txt'
    goChatting()
    pass


def submit(event=None):
    global certified
    if randomCode == Certify_entry.get():
        notice_label["text"] = 'Certified'
        print(Certify_entry.get())
        certified = True
    else:
        notice_label["text"] = 'Wrong Code!!'
        print(Certify_entry.get())
        print(randomCode)


def mailCertify(event=None):
    global randomCode
    import smtplib
    from email.message import EmailMessage
    name_re = re.compile(r'[a-z]{3,5}[0-9]{3,5}[a-z]{3,5}[0-9]{3,5}')
    randomCode = exrex.getone(name_re.pattern)
    print(randomCode)
    id = important.mailID
    passwd = important.mailPW
    mail_server = smtplib.SMTP(important.smtpServer, 587)
    mail_server.ehlo()
    mail_server.starttls()
    mail_server.login(id, passwd)
    msg = EmailMessage()
    msg['Subject'] = 'From FTP talk developer'
    msg['From'] = f'FTP talk developer <{important.mailID}>'
    msg['To'] = f'{Mail_entry.get()}'
    msg.set_content(f'From FTP talk developer\nCode: {randomCode}')
    mail_server.send_message(msg)
    mail_server.quit()


def register(event=None):
    session.cwd(rootFile)
    regMail = Mail_entry.get()
    regName = Name_entry.get()
    regPW = PW_entry.get()
    regPWAgain = PWAgain_entry.get()
    if regMail == '' or regName == '' or regPW == '' or regPWAgain == '':
        notice_label["text"] = 'Fill the entry!!'
        return
    if ' ' in regMail or ' ' in regName or ' ' in regPW or ' ' in regPWAgain:
        notice_label["text"] = 'Space is not allowed!!'
        return
    AllRex = r'^(.+)@(.+).(.+)$'  # 가입할때 빈칸 없게 조심해야 함
    RAll = re.compile(AllRex)
    if not RAll.search(regMail):
        notice_label["text"] = 'Invalid E-Mail format!!'
        return
    if not certified:
        notice_label["text"] = 'Submit code!!'
        return
    if regPW == regPWAgain:
        try:
            session.cwd(f'{rootFile}/{regMail}')
            # print("mail exist")
            notice_label["text"] = 'E-Mail Exist!!'
        except:
            session.cwd(rootFile)
            # print(session.pwd())
            session.mkd(regMail)
            # 사용자 정보 info에서 추가함
            userInfo = info() + f' Mail:{regMail} Name:{regName} PW:{regPW}'
            directlyWrite(infoFile, userInfo)
            session.cwd(f'{rootFile}/{regMail}')
            upload(infoFile)
            # only name 파일 생성
            directlyWrite(onlyNameFile, regName)
            session.cwd(f'{rootFile}/{regMail}')
            upload(onlyNameFile)
            # 친구 목록 생성
            directlyWrite(friendsListFile, None)
            session.cwd(f'{rootFile}/{regMail}')
            upload(friendsListFile)
            session.cwd(rootFile)
            # print(userInfo)
            goLogin()
    else:
        notice_label["text"] = 'PW not same!!'
        # print("PW not same")


def logIn(event=None):
    global infoName, Alert_label, logID, infoMail, myName, infoIPAddressExternal
    print("log in")

    logID = ID_entry.get()
    logPW = PW_entry.get()
    # print(logID)
    if logID == '' or logPW == '':
        Alert_label['text'] = 'Fill the entry'
        return
    try:
        session.cwd(f'{rootFile}/{logID}')
        print(f'dir ok {logID}')
        download(infoFile)
        download(onlyNameFile)
        print(f'down ok {infoFile}')
        newCheck = directlyRead(infoFile)
        print(f'new ok {newCheck}')
        myName = directlyRead(onlyNameFile)
        myName = myName.strip()
        print(f'내 이름: {myName}')
    except:
        session.cwd(rootFile)
        Alert_label['text'] = 'Wrong E-Mail'
        newCheck = None
    if newCheck:
        AllRex = r'Device:(.*) Internal:(.*) External:(.*) Mail:(.*) Name:(.*) PW:(.*)'
        RAll = re.compile(AllRex)
        MAll = RAll.search(newCheck)
        infoDeviceName = MAll.group(1)
        infoIPAddressInternal = MAll.group(2)
        infoIPAddressExternal = MAll.group(3)
        infoMail = MAll.group(4)
        infoName = MAll.group(5)
        infoPW = MAll.group(6)
        print("user info====" + infoDeviceName, infoIPAddressInternal, infoIPAddressExternal, \
        infoMail, infoName, infoPW)
        if infoMail == logID and infoPW == logPW:
            directlyWrite(infoFile, info() + f' Mail:{logID} Name:{infoName} PW:{logPW}')
            upload(infoFile)
            # 아이디 저장하고 로그인할 때
            if 'selected' in remember_button.state():
                encryptedID = simpleED.encrypt(logID)
                directlyWrite('rememberedID.txt', f'{encryptedID}')
            else:
                directlyWrite('rememberedID.txt', '')
            goMain()
        else:
            # print(infoName, logID, infoPW, logPW)
            Alert_label['text'] = 'Wrong Password'


# 이게 시작 호출임
try:
    os.chdir(localFolder)
except:
    os.mkdir(localFolder)
    os.chdir(localFolder)
goLogin()
Window.mainloop()
session.quit()
