# coding=utf-8
from Crypto.Cipher import AES
import base64
import json
import sys
import copy

profile = u"密码管理器欢迎您的使用，请牢记您的密钥! 版本(2018-09-17 caelum)"


def print_prompt(msg):
    print u"== " + msg


def exit_sys():
    print_prompt(u"88^__^88")
    sys.exit(0)


class AESCrypto:
    def __init__(self, key):
        key_len = 16
        if len(key) >= key_len:
            self.key = key[0:16]
        else:
            self.key = key + str((key_len - len(key)) * '0')
        self.mode = AES.MODE_CBC
        self.iv = b'0000000000000000'

    def encrypt(self, text):
        len_base = 16
        redundant = len(text) % len_base
        if redundant != 0:
            text += str((len_base - redundant) * '\0')
        cryptor = AES.new(self.key, self.mode, self.iv)
        cipher_text = cryptor.encrypt(text)
        return base64.b64encode(cipher_text)

    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(base64.b64decode(text))
        return plain_text.rstrip('\0')


class PwdMgr:
    magic_pwd = "hello world @caelum"

    def __init__(self):
        self.filename = 'pwd'
        self.aes = None
        self.pwd_list = {}
        self.pwd_list_saved = {}

    def set_key(self, key):
        self.aes = AESCrypto(key)

    def check_first_use(self):
        if len(self.pwd_list) == 0:
            return 1    # 首次进入系统
        if '0' not in self.pwd_list:
            return -1   # 文件已被损坏
        return 0        # 非首次进入系统

    def verify_key(self):
        if self.decrypt_str(self.pwd_list['0']['pwd']) == PwdMgr.magic_pwd:
            return True    # key正确
        else:
            return False   # key错误

    def encrypt_str(self, str, aes=None):
        if not aes:
            aes = self.aes
        return base64.b64encode(aes.encrypt(str))

    def decrypt_str(self, str, aes=None):
        if not aes:
            aes = self.aes
        return aes.decrypt(base64.b64decode(str))

    def init_pwd_list(self):
        try:
            with open(self.filename, 'r') as f:
                content = f.read()
        except IOError:
            content = ""
        if content and content != '':
            try:
                self.pwd_list = json.loads(content)
            except ValueError:
                return False
            self.pwd_list_saved = copy.deepcopy(self.pwd_list)
        return True

    def save_pwd_list(self):
        if len(self.pwd_list) == 0:
            self.pwd_list['0'] = {
                'name': '0',
                'account': 'python',
                'pwd': self.encrypt_str(PwdMgr.magic_pwd),
                'desc': 'verify key',
            }
        content = json.dumps(self.pwd_list, ensure_ascii=False)
        with open(self.filename, 'w') as f:
            f.write(content.encode('utf-8'))
            self.pwd_list_saved = copy.deepcopy(self.pwd_list)

    def check_is_modified(self):
        return cmp(self.pwd_list, self.pwd_list_saved) != 0

    def change_key(self, new_key):
        aes_old = self.aes
        self.set_key(new_key)
        for name, item in self.pwd_list.iteritems():
            pwd = self.decrypt_str(item['pwd'], aes_old)
            item['pwd'] = self.encrypt_str(pwd)

    def add_item(self, name, account, pwd, desc):
        if name == "0":
            return
        if name in self.pwd_list:
            print u'添加失败，[' + name + u'] 已经存在'
            return False
        self.pwd_list[name] = {
            'name': name,
            'account': account,
            'pwd': self.encrypt_str(pwd),
            'desc': desc,
        }
        return True

    def update_item(self, name, pwd, account=None, desc=None):
        if name == "0":
            return
        if name not in self.pwd_list:
            print_prompt(u'更新失败，没有找到 [' + name + u']')
            return False
        if account is None:
            account = self.pwd_list[name]['account']
        if desc is None:
            desc = self.pwd_list[name]['desc']
        self.pwd_list[name] = {
            'name': name,
            'account': account,
            'pwd': self.encrypt_str(pwd),
            'desc': desc,
        }
        return True

    def delete_item(self, name):
        if name == "0":
            return
        if name not in self.pwd_list:
            print_prompt(u'删除失败，没有找到 [' + name + u']')
            return False
        self.pwd_list.pop(name)
        return True

    def output_item(self, item):
        print u"名称：" + item['name']
        print u"账号：" + item['account']
        print u"密码：" + self.decrypt_str(item['pwd'])
        print u"描述：" + item['desc']
        print '=============================='

    def show_item(self, name):
        if name == "0":
            return
        if name not in self.pwd_list:
            print_prompt(u'查看失败，没有找到 [' + name + u']')
            return False
        self.output_item(self.pwd_list[name])
        return True

    def show_all(self):
        show_list = sorted(self.pwd_list.items(), key=lambda d: d[0])
        print '=============================='
        has_output = False
        for value in show_list:
            if value[0] != "0":
                has_output = True
                self.output_item(value[1])
        if not has_output:
            print u"密码数据为空"

    def show_all_name(self):
        show_list = sorted(self.pwd_list.items(), key=lambda d: d[0])
        print '=============================='
        has_output = False
        for value in show_list:
            if value[0] != "0":
                has_output = True
                print value[0]
        if not has_output:
            print u"密码数据为空"


def read_console():
    content = raw_input("## ").decode(sys.stdin.encoding)
    return content


def pwd_input():
    import platform
    plat = platform.system()
    if plat == "Windows":
        import msvcrt
        chars = []
        msvcrt.putch('#')
        msvcrt.putch('#')
        msvcrt.putch(' ')
        while True:
            new_char = msvcrt.getch()
            if new_char in '\r\n':      # 如果是换行，则输入结束
                msvcrt.putch('\n')
                break
            elif new_char == '\b':      # 如果是退格，则删除密码末尾一位并且删除一个星号
                if chars:
                    del chars[-1]
                    msvcrt.putch('\b')  # 光标回退一格
                    msvcrt.putch(' ')   # 输出一个空格覆盖原来的星号
                    msvcrt.putch('\b')  # 光标回退一格准备接受新的输入
            elif len(new_char) == 1:
                chars.append(new_char)
                msvcrt.putch('*')       # 显示为星号
        return ''.join(chars)
    else:
        return read_console()


def read_content(title, notnull, qualifier=u""):
    print_prompt(u"请输入" + qualifier + title + u"（0：返回）：")
    while True:
        if title == u"密码":
            content = pwd_input()
        else:
            content = read_console()
        if content == "" and notnull:
            print_prompt(title + u"不能为空，请重新输入（0：返回）：")
        else:
            return content


def cancel_msg(title):
    return u"已取消 [" + title + u"] 操作，返回上一级"


def ok_msg(title):
    return u"[" + title + u"] 成功，若要保存修改，请在主界面选择 [8] 进行保存"


def read_key():
    key_saved = None
    print_prompt(u"请输入密钥，密码以此密钥进行加解密，请牢记！（0：返回）：")
    while True:
        key = pwd_input()
        if key == "":
            print_prompt(u"密钥不能为空，请重新输入（0：返回）：")
            continue
        if key == "0":
            return key

        if key_saved:
            if key == key_saved:
                return key
            else:
                print_prompt(u"警告：两次输入密钥不一致")
                print_prompt(u"请输入密钥，密码以此密钥进行加解密，请牢记！（0：返回）：")
                key_saved = None
        else:
            print_prompt(u"请再次输入密钥进行确认：")
            key_saved = key


def inquiry_save(title, pwd_mgr):
    if not pwd_mgr.check_is_modified():
        return
    print_prompt(u"系统检测到您修改了密码数据，在" + title + u"前，请选择是否保存您的修改（y:是,n:否）：")
    while True:
        opt = read_console()
        if opt == "y" or "Y":
            pwd_mgr.save_pwd_list()
            return True
        elif opt == "n" or "N":
            return False
        else:
            print_prompt(u"请输入 y 或 n：")


class OperationMgr:
    def __init__(self, pwd_mgr):
        self.pwd_mgr = pwd_mgr
        self.op_list = {
            "1": self.show_all_name,
            "2": self.show_all_pwd,
            "3": self.show_item,
            "4": self.add_item,
            "5": self.update_item,
            "6": self.delete_item,
            "7": self.change_key,
            "8": self.save,
        }

    def run(self, op_num):
        if op_num in self.op_list:
            self.op_list[op_num]()
        else:
            print_prompt(u"警告：无效的操作")

    def show_all_name(self):
        self.pwd_mgr.show_all_name()

    def show_all_pwd(self):
        self.pwd_mgr.show_all()

    def show_item(self):
        name = read_content(u"项名称", True, u"要查看的")
        if name == "0":
            print_prompt(cancel_msg(u"查看单项密码"))
            return
        self.pwd_mgr.show_item(name)

    def write_item(self, add_or_update):
        if add_or_update == "add":
            title = u"添加密码项"
            name_qualifier = u"要添加的"
            account_notnull = True
            account_title = u"账号"
            desc_title = u"描述信息，可以为空"
        elif add_or_update == "update":
            title = u"修改密码项"
            name_qualifier = u"要修改的"
            account_notnull = False
            account_title = u"账号，按回车键跳过"
            desc_title = u"描述信息，按回车键跳过"
        else:
            return

        name = read_content(u"项名称", True, name_qualifier)
        if name == "0":
            print_prompt(cancel_msg(title))
            return
        account = read_content(account_title, account_notnull)
        if account == "0":
            print_prompt(cancel_msg(title))
            return
        while True:
            pwd = read_content(u"密码", True)
            if pwd == "0":
                print_prompt(cancel_msg(title))
                return
            pwd_again = read_content(u"密码", True, u"确认")
            if pwd_again == "0":
                print_prompt(cancel_msg(title))
                return
            elif pwd != pwd_again:
                print_prompt(u"警告：两次输入密码不一致")
            else:
                break
        desc = read_content(desc_title, False)
        if desc == "0":
            print_prompt(cancel_msg(title))
            return

        if add_or_update == "add":
            self.pwd_mgr.add_item(name, account, pwd, desc)
        elif add_or_update == "update":
            self.pwd_mgr.update_item(name, pwd, account, desc)
        print_prompt(ok_msg(title))

    def add_item(self):
        self.write_item("add")

    def update_item(self):
        self.write_item("update")

    def delete_item(self):
        title = u"删除密码项"
        name = read_content(u"项名称", True, u"要删除的")
        if name == "0":
            print_prompt(cancel_msg(title))
            return
        if self.pwd_mgr.delete_item(name):
            print_prompt(ok_msg(title))

    def change_key(self):
        title = u"修改密钥"
        inquiry_save(title, self.pwd_mgr)
        key = read_key()
        if key == "0":
            print_prompt(cancel_msg(title))
            return
        self.pwd_mgr.change_key(key)
        self.pwd_mgr.save_pwd_list()
        print_prompt(u"修改密钥成功，请牢记您的新密钥")

    def save(self):
        self.pwd_mgr.save_pwd_list()
        print_prompt(u"保存成功")


def main():
    print_prompt(profile)
    pwd_mgr = PwdMgr()
    if not pwd_mgr.init_pwd_list():
        print u"告诉您一个不幸的消息，密码数据已被损坏，请删除pwd文件重新使用"
        exit_sys()
    ret = pwd_mgr.check_first_use()
    if ret == 1:
        key = read_key()
        if key == "0":
            exit_sys()
        pwd_mgr.set_key(key)
        pwd_mgr.save_pwd_list()
        print_prompt(u"密钥初始化成功！\n")
    elif ret == 0:
        print_prompt(u"系统需要验证您的身份，请输入密钥（0：返回）：")
        while True:
            key = pwd_input()
            if key == "":
                print_prompt(u"密钥不能为空，请重新输入：")
                continue
            if key == "0":
                exit_sys()
            pwd_mgr.set_key(key)
            if pwd_mgr.verify_key():
                print_prompt(u"密钥验证通过！")
                break
            else:
                print_prompt(u"密钥错误，请重新输入：（0：返回）")
    else:
        print u"告诉您一个不幸的消息，密码数据已被损坏，请删除pwd文件重新使用"
        exit_sys()

    op_mgr = OperationMgr(pwd_mgr)
    print ""
    while True:
        print_prompt(u"请选择以下操作：1.显示全部项名称；2.显示全部密码；3.查看单项密码；4.添加密码项；5.修改密码项；" 
                     u"6.删除密码项；7.修改密钥；8.保存所有修改；0.退出")
        op = read_console()
        if op == "0":
            inquiry_save(u"退出系统", pwd_mgr)
            exit_sys()
        else:
            op_mgr.run(op)
        print ""


if __name__ == '__main__':
    main()

