from os import getcwd
import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
import json
from difflib import SequenceMatcher


def getcurrenttime():
    return datetime.now().strftime("%m/%d/%Y, %H:%M:%S")


red = '\33[31m'
white = '\33[0m'
green = '\33[32m'
violet = '\33[35m'

maindir = getcwd() + "/"
matching_min_ratio = 0.69

class Manager:

    def __init__(self,master_password, len_salt = 16, testphrase= "brunorossi", load = False):
        if load:
            self.load(master_password)
            return
        self.Saved_Passwords = []
        self.salt = os.urandom(len_salt)
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=390000)
        self.password = base64.urlsafe_b64encode(self.kdf.derive(master_password.encode("utf-8")))
        self.FernetObj = Fernet(self.password)
        self.Notes = []
        self.testphrase = testphrase
        self.testphrase_hash = self.encryptsomething(self.testphrase).encode("utf-8")
        self.otp = False
        self.counter = 0

    def encryptsomething(self, cryptohash):
        if type(cryptohash) != bytes:
            cryptohash = cryptohash.encode("utf-8")
        return self.FernetObj.encrypt(cryptohash).decode("utf-8")

    def refreshkdf(self):
        self.kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=self.salt,iterations=390000)
        return self.kdf

    def check(self, mp_user, ret):
        self.refreshkdf()
        if base64.urlsafe_b64encode(self.kdf.derive(mp_user.encode("utf-8"))) == self.password:
            if type(ret) != bool:
                if ret.__contains__("salt"):
                    len_salt = int(ret[4:])
                    if len_salt % 16 != 0:
                        return self.change_salt(mp_user,len_salt=len_salt)
                    else:
                        return print(f"Salt len too high. 16 > lenght salt < 64. Your input: {len_salt}")
            return True
        return False

    def change_master(self, new_master,):
        new_pwds = []
        for pwd in self.Saved_Passwords:
            new_pwd_dict = {}
            for k,v in pwd.items():
                if k == "password":
                    v = self.decryptsomething(v)
                new_pwd_dict[k] = v
            new_pwds.append(new_pwd_dict)
        new_notes = []
        for note in self.Notes:
            new_note = note
            for k, v in note.items():
                if k == "note_text":
                    new_note["note_text"] = self.decryptsomething(note["note_text"])
            new_notes.append(note)
        self.refreshkdf()
        self.password = base64.urlsafe_b64encode(self.kdf.derive(new_master.encode("utf-8")))
        self.FernetObj = Fernet(self.password)
        for pwd in new_pwds:
            pwd["password"] = self.encryptsomething(pwd["password"])
        self.Saved_Passwords = new_pwds
        for note in new_notes:
            note["note_text"] = self.encryptsomething(note["note_text"])
        self.Notes = new_notes



    def change_salt(self,mp_user, len_salt : int):
        old = open(maindir + "save.txt", "r").read()

        self.salt = os.urandom(len_salt)
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=390000)

        self.change_master(mp_user)


    def decryptsomething(self, cryptohash):
        if type(cryptohash) != bytes:
            cryptohash = cryptohash.encode("utf-8")
        return self.FernetObj.decrypt(cryptohash)

    def new_login(self, plain_password : str, username : str, url : str):
        plain_password = self.encryptsomething(plain_password)
        a = {
            "password" : plain_password,
            "username" : username,
            "url" : url,
            "date_added" : getcurrenttime()
        }
        self.Saved_Passwords.append(a)
        self.save()

    def new_note(self,note_text,password = None):

        note_text = self.encryptsomething(note_text)
        if password:
            Note = {
                "note_text": note_text,
                "date_added": getcurrenttime(),
                "password": "1",
            }
        else:
            Note = {
                "note_text": note_text,
                "date_added": getcurrenttime(),
                "password" : "0",
            }

        self.Notes.append(Note)
        self.save()

    def all(self,intent):
        if intent == "pwds":
            a = [i for i in range(len(self.Saved_Passwords))]
            return self.expose_pwd(a)
        elif intent == "notes":
            b = [i for i in range(len(self.Notes))]
            return self.expose_note(b)
        a = [i for i in range(len(self.Saved_Passwords))]
        b = [i for i in range(len(self.Notes))]
        if not intent:
            if not a and b:
                return self.expose_note(b)
            if not b and a:
                return self.expose_pwd(a)
            if a and b:
                return self.expose_pwd(a) + self.expose_note(b)
            if not a and not b:
                return "-1"



    def save(self):
        savefile = open(maindir + "save.txt", "w")
        p = json.dumps(self.Saved_Passwords)
        n = json.dumps(self.Notes)
        s = json.dumps(base64.b64encode(self.salt).decode("utf-8"))
        testp = json.dumps(self.testphrase)
        testp_h = json.dumps(self.encryptsomething(self.testphrase))
        if self.otp:
            self.otp = 1
        else:
            self.otp = 0
        savelist = json.dumps([p,n,s,testp,testp_h,[self.otp,self.counter]])
        savefile.write(savelist)
        savefile.close()
        return 0

    def load(self,master_password):
        savefile = open(maindir + "save.txt", "r").read()
        a = json.loads(savefile)
        pwds,notes,salt, testp, testp_h,otp,counter = json.loads(a[0]),json.loads(a[1]),json.loads(a[2]), json.loads(a[3]), json.loads(a[4]),json.loads(str(a[5][0])), json.loads(str(a[5][1]))
        self.Saved_Passwords = pwds
        self.Notes = notes
        self.salt = base64.b64decode(salt)
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=390000)
        self.password = base64.urlsafe_b64encode(self.kdf.derive(master_password.encode("utf-8")))
        self.FernetObj = Fernet(self.password)
        self.testphrase = testp
        self.testphrase_hash = testp_h.encode("utf-8")
        self.counter = counter
        if otp == 1:
            otp_user = input("OTP: ").encode("utf-8")
            self.otp = True
            if self.otp:
                a = self.validate_otp(otp_user)
                if a[0]:
                    print(F"{red}OTP: {green}OK {white}|{red} NEW OTP: {green}{a[1].decode('utf-8')}{white}")
                else:
                    quit("Bad OTP or Master Password...")
        elif otp == 0:
            self.otp = False

        return self.trystart()

    def search(self,*args):
        res, res_notes = [], []
        for arg in args:
            for pwd in self.Saved_Passwords:
                for k,v in pwd.items():
                    if k == "password":
                        v = self.decryptsomething(v.encode("utf-8")).decode("utf-8")
                    if SequenceMatcher(None, v, arg).ratio() > matching_min_ratio:
                        res.append(self.Saved_Passwords.index(pwd))
                        break
            for note in self.Notes:
                for k,v in note.items():
                    if k == "note_text":
                        v = self.decryptsomething(v.encode("utf-8")).decode("utf-8")
                    v = v.replace("\n"," ").rstrip("\\x").split(" ")
                    for i in v:
                        if SequenceMatcher(None, i, arg).ratio() > matching_min_ratio:
                            res_notes.append(self.Notes.index(note))
                            break
        return res,res_notes

    def expose_pwd(self, pwds):
        if not pwds:
            return -1
        result = []
        for arg in pwds:
            arg = self.Saved_Passwords[arg]
            partial = []
            for k,v in arg.items():
                if k == "password":
                    v = self.decryptsomething(v.encode("utf-8")).decode("utf-8")
                partial.append(f"|{violet}{k} {white}:{red} {v}{white}  ")
            result.append("".join(partial))
            result.append("\n")
        t = ""
        for i in range(int(int(len(max(result))) / 2)):
            t += "_"
        result.insert(0,t +"\n")
        result.insert(-1,"\n" + t)
        return "".join(result)


    def trystart(self):
        try:
            a = bool(self.decryptsomething(self.testphrase_hash).decode("utf-8") == self.testphrase)
            if a:
                return print(f"{green}Correct Password{white}")
        except InvalidToken:
            print(f"{red}WrOnG_PaSsWoRd{white}\n")
            print("Failed_initializaition. Quitting...")
            return self.load(input(f"Master_Password {red} maybe correct this time :{white} "))

    def expose_note(self, res_notes):
        result = ""
        if not res_notes:
            return -1
        if len(res_notes) > 1:
            result += f"Multiple ({red}{str(len(res_notes))}{white}) results found in the notes db\n"
        for note in res_notes:
            result += f"{green}note n. {red}{note} {white}: \n\t\t\t "
            note = self.Notes[note]

            if note["password"] == "1":
                print("some notes are password protected")
                mp_user = input("master_password: ")
                if self.check(mp_user,ret=True):
                    note = self.decryptsomething(note["note_text"]).decode("utf-8")
            else:
                note = self.decryptsomething(note["note_text"]).decode("utf-8")
            note = note.replace("\\x" ,"").replace("\\", " ")
            result+= note

        return result


    def stats(self):
        p_count,n_count = len(self.Saved_Passwords), len(self.Notes)
        return f"Secured Passwords: {red}{p_count}{white} , secured notes {red}{n_count}{white}"

    def validate_otp(self, otp_user,first = False):
        from cryptography.hazmat.primitives.twofactor.hotp import HOTP
        from cryptography.hazmat.primitives.hashes import SHA1
        if first:
            hotp = HOTP(self.password, 6, SHA1())
            self.otp = True
            if self.counter != 0:
                self.counter = 0
            return hotp.generate(self.counter)

        hotp = HOTP(self.password, 6, SHA1()) # lenght otp
        hotp_value = hotp.generate(self.counter)
        if hotp_value != otp_user:
            return [False, 0]
        else:
            self.counter += 1
            self.save()
            return [True, hotp.generate(self.counter)]



def get_multi_input():
    text = ""
    first = True

    while True:
        if first:
            i = input("Write Anything: \\x at the end to save and exit\n")
            text += i + "\n"
            first = False
        else:
            i = input("")
            text += i + "\n"
        if not i:
            pass
        if i.__contains__("\\x"):
            return text


def startcheck():
    global Master
    file = open(maindir + "save.txt", "r").read()
    if file:
        print("SaveFile: TRUE")
        if input("load? y/n : ") == "y":
            mp = input("Master_Password : ")
            Master = Manager(mp, load=True)
            return Master
        else:
            quit("Backup and remove your old savefile first!!!")

    else:
        print("SaveFile : FALSE")
        mp = input("Master_Password: ")
        try:
            len_salt = int(input("Salt Lenght (must be a multiple of 16) : "))
        except ValueError:
            return startcheck()
        if len_salt % 16 != 0:
            return startcheck()
        Master = Manager(mp, len_salt)
        Master.save()
        return Master


def prompt(*args): ### WIP Function Spoiler: it doesn't work.
    import keyboard
    print("press down to start")
    while 1:
        for i in range(len(args)):
            if keyboard.is_pressed("down") or keyboard.is_pressed("k"):
                Master.expose_pwd(Master.Saved_Passwords[args[i]])
            if keyboard.is_pressed("up") or keyboard.is_pressed("o"):
                selected = Master.Saved_Passwords[args[i]]
                for k,v in selected:
                    print(f"{k} : {v}")
                    while 1:
                        if keyboard.is_pressed("down") or keyboard.is_pressed("k"):
                            continue
                        else:
                            if k == "password":
                                v = Master.decryptsomething(v)




def gen(lenght, level):
    # 5 levels
    import string
    from random import choice,randint
    chars_l = list(string.ascii_lowercase)
    chars_u = list(string.ascii_uppercase)
    numbers = list(string.digits)
    simbols = list(string.punctuation)
    big = chars_l + chars_u + numbers
    chance_symbol = level * 10
    res = ""
    for i in range(lenght):
        r = randint(0,len(big) + 32) # 32 = len(simbols) aka string.punctuation
        if r <= chance_symbol:
            res += choice(simbols)
        else:
            res += choice(choice(big))
    return res

def trytomatch(command):
    command = command.split(" ")
    args = ""
    if len(command) > 1:
        args = command[1:]
    command = command[0]
    list_of_commands = ["new","search","settings","gen","save","load","all","printall","help","derive"]
    for i in range(len(list_of_commands)):
        if SequenceMatcher(None,command,list_of_commands[i]).ratio() > 0.69:
            if args:
                return list_of_commands[i] + " " + " ".join(args)
            else:
                return list_of_commands[i]


def main():
    while 1:
        try:
            command = input(f"{green}com: {white}")
        except ValueError:
            continue
        command = trytomatch(command)
        if not command:
            print(f"{red}command 2much mispelled,retry...{white}")
            continue
        if command.__contains__("new") or command == "new":
            if command == "new":
                intent = input("new password : 1\nnew note : 2")
                if intent == "1":
                    intent = "pwd"
                elif intent == "2":
                    intent = "note"
                else:
                    print("invalid input")
                    continue
                if intent == "pwd":
                    pwd,username,url = input("password: "),input("username: "),input("url: ")
                    Master.new_login(pwd,username,url)
                    print("Password Added.")
                elif intent == "note":
                    note = get_multi_input()
                    Master.new_note(note)

            command = command.split(" ")[1:]
            intent = command[0]
            if intent == "pwd":
                pwd,username,url = command[1],command[2],command[3]
                Master.new_login(pwd, username, url)
            elif intent == "note":
                note_text = get_multi_input()
                if input("protect note with password? y/n ") == "y":
                    Master.new_note(note_text,True)
                else:
                    Master.new_note(note_text,False)
        if command.__contains__("search"):
            com = command.split(" ")[1:]
            res,res_notes = Master.search(*com)
            if res == -1:
                print("Not Found")
            else:
                if not res:
                    print(f"{red}no result in pwds{white}\n")
                else:
                    print(Master.expose_pwd(res))
                if res_notes:
                    print(Master.expose_note(res_notes))
                    try:
                        #prompt(res)
                        pass
                    except OSError: # OSerror
                        print(f"{red} ERROR! Must run the program as admin to use the $prompt$ function.")
        if command == "settings":
            while 1:
                print(Master.stats())
                print(Master.salt)
                print("s to generate new salt, sN to generate new salt with custom lenght\nexample s53 generates a salt 53 chars long")
                print("p_change to change Master Password")
                if not Master.otp:
                    print(f"otp: {red}DEACTIVATED")
                    print(f"{white}use otp_on to enable")
                elif Master.otp:
                    print(f"otp: {green}ON.")
                    print(f"{white} otp_off to disable")
                command = input(f"{green}com_settings: ")
                if command.__contains__("salt"):
                    if command == "salt":
                        if Master.check(input("Master_Password: "), ret="salt16"):
                            print("OK")
                            Master.save()
                    elif command.__contains__("salt"):
                        len_salt = int(command[4:])
                        if Master.check(input("Master_Password: "), ret=f"salt{len_salt}"):
                            print("OK")
                            Master.save()
                if command == "otp_on":
                    if Master.check(input("Master Password: ")):
                        a = Master.validate_otp(000000,True)
                        Master.save()
                        print(f"NEW OTP: {a.decode('utf-8')}")
                if command == "otp_off":
                    master_password = input("Master Password: ")
                    if Master.check(master_password,True):
                        Master.otp = False
                        Master.counter = 0
                    else:
                        print(f"{red}ERROR:Wrong Password{white}")

                elif command == "p_change":
                    if Master.check(input("Master_password : "), ret=False):
                        Master.change_master(input("New_Master_Password: "))
                        Master.save()
                    else:
                        print(f"{red}Password's Wrong{white}")
                else:
                    break
        if command.__contains__("gen"):
            if command == "gen":
                generated = gen(10,4)
            else:
                try:
                    command = command.split(" ")[1:]
                    lenght = int(command[0])
                    level = int(command[1])
                    if level > 5:
                        print(f"ERROR: Level is too high. Max is 5. Your input: {lenght}")
                        continue
                except (ArithmeticError,ValueError):
                    print("ERROR: non numeric inputs given!")
                    continue
                except IndexError:
                    print("ERROR: not enough values to unpack")
                    continue
                generated = gen(lenght,level)
            print(f"Generated password: {red}{generated}{white}")
            continue
        if command == "g":
            print(Master.trystart())
        if command == "save":
            Master.save()
        if command == "load":
            Master.load(input("Master_Password: "))
        if command == "all" or command == "printall":
            intent = ""
            if command[1]:
                if command[1] == "pwds" or command[1] == "pwd":
                    intent = "pwds"
                elif command[1] == "notes" or command[1] == "note":
                    intent = "notes"
                    
            if intent:
                print(Master.all(intent))
            else:
                print(Master.all(""))
        if command.__contains__("help"):
            command = command.split(" ")[1:]
            intent = ""
            try:
                intent = command[0]
            except IndexError:
                intent = "main"
            if intent == "main":
                print("".join(v for v in help_dict.values()))
            else:
                for k,v in help_dict.items():
                    for i in k:
                        M = SequenceMatcher(None,i,intent).ratio()
                        if  M > 0.69:
                            print(v)
                        elif 0.60 < M < 0.69:
                            print(f"{red}did u mean : {red}{f'{white} or{red} '.join(list(k))}{white}")


help_dict = {
    ("pwd","password", "new password") : f"{red}new pwd password username url {white}- {red}to add a new login to the database.{white}\n"
                                         f"{white}\texample: {red}new pwd test1_AA testuser1 testsite.com {white}adds a new password with the given parameters",
    ("note","notes","add note") : f"{red}new note {white}-{red} to add a new safe-note to the database.\n{white}",
    ("search", "search", "find") : f"{red}search search_hint {white}-{red} each hint can be a single world and you can put as many as you want separated by a space\n"
                                          f"{white}\texample: {red}search test1_AA {white}to search trough {red}password{white} \n"
                                          f"{white}\tNote: {red}If the results are more than one they will be also shown in the results prompt.{white}\n",
    "various" : f"{red}settings{white} - {red} prompts the settings\n{red}help{white} or {red}? {white}- {red}prompts this\n{red}help singlecommand{white} to prompt syntax help for a command\n{white}",
    ("all","printall") : f"{red}all {white}- {red}print all the elements{white}, see settings for beautification.{white}\n",

}



if __name__ == "__main__":
    Master = startcheck()
    main()
