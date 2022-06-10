import hashlib
import json
import requests

from time import time, ctime,sleep
from uuid import uuid4
from flask import Flask, jsonify, request
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from urllib3.exceptions import ConnectTimeoutError
import socket
import threading
import PySimpleGUI as sg

def get_currentTime():  ##获取当前时间
    currentTime = ctime()
    return currentTime


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    # rint(type(ip))
    return ip


def rsakeys():  ##生成公钥私钥函数
    length = 1024
    privatekey = RSA.generate(length, Random.new().read)
    publickey = privatekey.publickey()
    return privatekey, publickey


def shaHash(data):  ##私钥加密，公钥验证中的哈希函数
    bdata = bytes(data, encoding="utf-8")
    hashOfdata = SHA.new(bdata)
    return hashOfdata


def sign(privatekey, hashOfData):  ##签名函数   参数:私钥，哈希之后的消息
    signer = PKCS1_v1_5.new(privatekey)
    signature = signer.sign(hashOfData)
    # signature64=base64.b64encode(signature)
    return signature


def verify(publickey, signature, hashOfData):  ##验证函数 #参数  公钥，签名，哈希后的消息
    verifier = PKCS1_v1_5.new(publickey)  ##用公钥生成验证器
    return verifier.verify(hashOfData, signature)  ##用验证器验证哈希后的消息和签名


class Blockchain(object):
    def __init__(self):
        ...
        self.nodes = {}
        # 用 set 来储存节点，避免重复添加节点.
        ...
        self.cnt = 0
        self.chain = []
        self.current_transactions = []
        self.mineTransaction = []
        # 创建创世区块
        timeStamp = "2021/12/31"
        self.new_block(100, timeStamp, 1)
        self.BlockCnt = 0
        self.__flag = threading.Event()
        self.__flag.set()
        self.__exit = False
        # self.new_block(previous_hash=1,timeStamp,proof=100)

    def register_node(self, address, key):
        """
        在节点列表中添加一个新节点
        :param address:
        :return:
        """
        if address in self.nodes:
            message = "You are already registered."
        else:
            message = "Registing success!"
            self.nodes[address] = key
        print(self.nodes)
        return message

    def valid_chain(self, chain):
        """
        确定一个给定的区块链是否有效
        :param chain:
        :return:
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n______\n")
            # 检查block的散列是否正确
            if block['previous_hash'] != self.hash(last_block):
                return False
            # 检查工作证明是否正确 previous_hash,timeStamp,proof
            if not self.valid_proof(block['previous_hash'], block['timestamp'], block['proof'], block['transactions']):
                return False

            last_block = block
            current_index += 1
        return True

    def decide_eq(self, chain):
        if self.chain[0]['index'] != chain[0]['index']:
            return False
        if self.chain[0]['proof'] != chain[0]['proof']:
            return False
        if self.chain[0]['transactions'] != chain[0]['transactions']:
            return False
        if self.chain[0]['timestamp'] != chain[0]['timestamp']:
            return False
        if self.chain[0]['previous_hash'] != chain[0]['previous_hash']:
            return False
        return True

    def resolve_conflicts(self):
        """
        共识算法
        :return:
        """
        neighbours = self.nodes
        new_chain = None
        # 寻找最长链条
        max_length = len(self.chain)

        # 获取并验证网络中的所有节点的链
        for ip, portKey in neighbours.items():
            if ip==my_ip:
                continue
            response = requests.get(f'http://{ip}:{portKey[0]}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # 检查长度是否长，链是否有效
                if length > max_length and self.valid_chain(chain) and self.decide_eq(chain):
                    max_length = length
                    new_chain = chain

        # 如果发现一个新的有效链比当前的长，就替换当前的链
        if new_chain:
            self.chain = new_chain
            return True
        return False

    def new_block(self, proof, timeStamp, previous_hash=None):
        """
        创建一个新的块并将其添加到链中
        :param proof: 由工作证明算法生成证明
        :param previous_hash: 前一个区块的hash值
        :param timeStamp: 时间戳
        :return: 新区块
        """
        block = {
            'index': len(self.chain) + 1,
            'timestamp': timeStamp,
            'transactions': self.mineTransaction,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        self.chain.append(block)
        return block

    def new_transaction(self, sender, message, time, ipcnt):
        # 将新事务添加到事务列表中
        """
        Creates a new transaction to go into the next mined Block
        :param sender:发送方的地址
        :param message:消息
        :param time:当前时间
        :param ipcnt:标识
        :return:保存该事务的块的索引
        """
        self.current_transactions.append({
            'sender': sender,
            'message': message,
            'time': time,
            'ipcnt': ipcnt,
        })

        # return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        """
        给一个区块生成 SHA-256 值
        :param block:
        :return:
        """
        # 必须确保这个字典（区块）是经过排序的，否则将会得到不一致的散列
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        # 返回链中的最后一个块
        return self.chain[-1]

    def proof_of_work(self, previous_hash, transactions):
        # 工作算法的简单证明
        proof = 0
        timeStamp = str(time())
        while self.valid_proof(previous_hash, timeStamp, proof, transactions) is False:
            self.__flag.wait()
            if self.__exit:
                return 0, 0
            proof += 1
            # if proof % 10000 == 0:
            #     print("proof = {:d}".format(proof))
            if proof == 2 ** 32:
                proof = 0
                timeStamp = str(time())
        return proof, timeStamp

    def run(self):
        self.__flag.set()
        self.__exit = False

    def pause(self):
        self.__flag.clear()

    def resume(self):
        self.__flag.set()

    def stop(self):
        self.__flag.set()  # 将线程从暂停状态恢复, 如何已经暂停的话
        self.__exit = True

    def valid_proof(self, previous_hash, timeStamp, proof, transactions):
        # 验证证明
        data = ''
        for i in transactions:
            data += i['sender'] + i['message'] + i['time']
        guess = previous_hash + timeStamp + data + str(proof)
        guess = bytes(guess, encoding="utf-8")
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:5] == "00000"


def valid_request(address):
    ips = set([(str(node).split(':'))[0] for node in blockchain.nodes.keys()])
    return address in ips


def mine():
    # 运行工作算法的证明来获得下一个证明。
    # 必须得到一份寻找证据的奖赏。
    blockchain.new_transaction(
        sender="0",
        message=my_ip + " has created this block!",
        time=get_currentTime(),
        ipcnt=my_ip + "/" + str(blockchain.cnt)
    )
    blockchain.cnt += 1
    blockchain.mineTransaction = blockchain.current_transactions
    transactions = blockchain.current_transactions
    blockchain.current_transactions = []
    last_block = blockchain.last_block
    previous_hash = blockchain.hash(last_block)
    blockchain.run()
    proof, timeStamp = blockchain.proof_of_work(previous_hash, transactions)
    if proof == timeStamp == 0:
        return
    # 通过将其添加到链中来构建新的块
    block = blockchain.new_block(proof, timeStamp, previous_hash)
    json_data = {"NewBlock": block}
    for node, portKey in blockchain.nodes.items():  ##全网通知
        if hostIP == node + f":{portKey[0]}":
            continue
        try:
            r = requests.post("http://" + node + f":{portKey[0]}" + "/block/new", json=json_data,timeout=3)
            print(r.text)
        except requests.exceptions.Timeout as e:
            print(str(e))
            continue
    blockchain.BlockCnt = blockchain.BlockCnt + 1
    if blockchain.BlockCnt >= 3:
        result = consensus()
        print(result['message'])
        blockchain.BlockCnt = 0


# 解决冲突
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return response


# 实例化节点
path1 = "resources"
app = Flask("Decentrailized Network", static_folder=path1)
port = 5000
my_ip=get_host_ip()
hostIP = my_ip + f":{port}"
# print(hostIP)
# 为该节点生成一个全局惟一的地址
node_identifier = str(uuid4()).replace('-', '')
print(node_identifier)
# 实例化Blockchain类
blockchain = Blockchain()
private_key, pub_key = rsakeys()
pub_key = pub_key.exportKey().hex()
blockchain.nodes[my_ip] = (port, pub_key)
event = threading.Event()

# 进行挖矿请求


# 创建交易请求
@app.route('/transactions/new', methods=['POST'])
def new_transactions():
    values = request.get_json()

    # 检查所需要的字段是否位于POST的data中
    required = ['sender', 'message', 'time', 'sign', 'ipcnt']
    if not all(k in values for k in required):
        return jsonify('Missing values'), 400
    sender_ip = values['sender']
    ip = request.remote_addr
    if not valid_request(ip):  ##判断发来http请求的节点是否注册
        return jsonify('This ip has not registered'), 400
    publickey = blockchain.nodes[sender_ip][1]  ##得到发消息节点的公钥
    publickey = bytes.fromhex(publickey)
    publickey = RSA.import_key(publickey)

    sign = values['sign']
    data = values['sender'] + values['message'] + values['time']  ##消息数据
    hashOfData = shaHash(data)  ##消息数据的哈希
    if type(sign) is not str:
        return "Error: Please supply a valid Sign", 400
    sign = bytes.fromhex(sign)
    if not verify(publickey, sign, hashOfData):  ##公钥验证
        return jsonify('False message or message tampering'), 400
    # 创建一个新的事务
    index = blockchain.new_transaction(values['sender'], values['message'], values['time'], values['ipcnt'])
    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


# 获取所有快信息
@app.route('/chain', methods=['GET'])
def full_chain():
    ip = request.remote_addr
    if not valid_request(ip):
        return 'This ip has not registered', 400
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


# 添加节点
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    ip = request.remote_addr
    print(ip)

    # 检查所需要的字段是否位于POST的data中
    required = ['port', 'pub_key']
    if not all(k in values for k in required):
        return 'Missing values', 400
    reg_port = values.get('port')
    key = values.get('pub_key')
    if type(reg_port) is not int:
        return "Error: Please supply a valid port", 400
    if type(key) is not str:
        return "Error: Please supply a valid pubKey", 400
    reg_key = key
    nodes = ip
    dic = {nodes: (reg_port, reg_key)}
    print(dic)
    json_data = {'nodes': dic}

    for node, portKey in blockchain.nodes.items():
        if hostIP == node + f":{portKey[0]}":
            print("Self ip:", node)
            continue
        try:
            r = requests.post("http://" + node + f":{portKey[0]}" + "/nodes/add", json=json_data,timeout=3)
            print(r.text)
        except ConnectTimeoutError:
            print("Connect", node, "Error.")
            continue

    message = blockchain.register_node(nodes, (reg_port, reg_key))

    response = {
        'message': message,
        'total_nodes': blockchain.nodes
    }
    return jsonify(response), 201


@app.route('/nodes/add', methods=['POST'])
def add_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400
    ip = request.remote_addr
    if not valid_request(ip):
        return "Error: Please register in before you add nodes", 400

    for key, value in nodes.items():
        message = blockchain.register_node(key, value)

    response = {
        'message': message,
        'total_nodes': blockchain.nodes,
    }

    return jsonify(response), 201


@app.route('/block/new', methods=['POST'])
def addBlock():
    blockchain.pause()
    data = request.get_json()
    ip = request.remote_addr
    if not valid_request(ip):
        return "This ip has not registered.",400
    block = data['NewBlock']
    if not blockchain.valid_proof(block['previous_hash'], block['timestamp'], block['proof'],
                                  block['transactions']):  ##检查这个块的证明
        blockchain.resume()
        return "Block is invalid",400
    last_block = blockchain.last_block
    previous_hash = blockchain.hash(last_block)
    if previous_hash != block['previous_hash']:  ##看块内previous_hash是否等于前一个块的hash
        blockchain.resume()
        return "previous_hash wrong",400
    blockchain.stop()
    event.clear()
    blockchain.chain.append(block)  ##上链
    for i in block['transactions']:
        for j in blockchain.current_transactions[:]:
            if i['ipcnt'] == j['ipcnt']:
                blockchain.current_transactions.remove(j)
    event.set()
    return "block added successfully",200

def run_mine():
    sleep(4)
    while True:
        event.wait()
        mine()
        sleep(3)

def regiser():
    layout = [
        [sg.Text("please input the ip address of the node you want to register(format:xxx.xxx.xxx.xxx):")],
        [sg.Input(key="__IP__")],
        [sg.Button("OK"),sg.Button("Cancel")]
    ]
    window = sg.Window("Register", layout)
    event,value = window.read()
    if event in [None,'Cancel']:
        window.close()
        return
    ip = value['__IP__']
    if ip not in blockchain.nodes.keys():
        url2 = "http://"+ip+":5000/nodes/register"
        data2 = {'port': 5000, 'pub_key': pub_key}
        try:
            reply = requests.post(url2, json=data2,timeout=3)
            nodes = reply.json()['total_nodes']
            blockchain.nodes.update(nodes)
            sg.Popup(reply.text)
        except requests.exceptions.Timeout as e:
            sg.Popup(str(e))
    window.close()

def post():
    if len(blockchain.nodes) == 1:
        sg.Popup("You have not registered to any nodes!")
        return
    layout = [
        [sg.Text("please input the message:")],
        [sg.Input(key="__MES__")],
        [sg.Button("OK"),sg.Button("Cancel")]
    ]
    window = sg.Window("Sending Message", layout)

    event,value = window.read()
    if event in [None,"Cancel"]:
        window.close()
        return
    timestamp=get_currentTime()
    ip=my_ip
    message = value["__MES__"]
    hashOfData=shaHash(ip+message+timestamp)
    si=sign(private_key,hashOfData)
    ipcnt=my_ip+"/"+str(blockchain.cnt)
    data={"sender":my_ip,"message":message,"time":timestamp,"sign":si.hex(),"ipcnt":ipcnt}
    blockchain.cnt+=1
    blockchain.new_transaction(my_ip,message,timestamp,ipcnt)
    for ip in blockchain.nodes.keys():   ##向全网节点发
        if ip != my_ip:
            url = "http://" + ip + ":5000/transactions/new"
            try:
                reply=requests.post(url,json=data,timeout=3)
                sg.Popup(reply.text)
            except requests.exceptions.Timeout as e:
                sg.Popup(str(e))
    window.close()

def get_messages():
    oneTime = 0
    layout = [
        [sg.Text("",key="0")],
        [sg.Text("",key="1")],
        [sg.Text("",key="2")],
        [sg.Text("",key="3")],
        [sg.Button("Next"),sg.Button("OK")]
    ]
    window = sg.Window("Messages",layout=layout,finalize=True)
    partion = "*"*60
    print(partion)
    for block in blockchain.chain:
        if block['previous_hash'] == 1:
            continue
        for trans in block['transactions']:
            text = ''
            sender = trans['sender']
            if sender == "0":
                continue
            message = trans['message']
            time = trans['time']
            text += '\n**' + partion + '**\n'
            text += f'**{sender}:' + '\n'
            m = ' ' * ((len(partion) - len(message)) // 2) + message
            text += '**' + m + '\n'
            text +='**' + ' ' * (len(partion) - len(time)) + time + '\n'
            text += "**" + partion + "**"
            window[str(oneTime)].update(text)
            oneTime += 1
            if oneTime >= 4:
                layout = [
                    [sg.Text(text)],
                    [sg.Button("Next"), sg.Button("OK")]
                ]
                event, value = window.read()
                if event in [None,"OK"]:
                    window.close()
                    return
                elif event == "Next":
                    for i in range(4):
                        window[str(i)].update('')
                    oneTime = 0
    event, value = window.read()
    window.close()


def client():
    layout = [
        [sg.Text("1.  Register to a node")],
        [sg.Text("2.  Post some message")],
        [sg.Text("3.  Get all messages")],
        [sg.Input(key="__CHOICE__")],
        [sg.Button("OK"),sg.Button("Cancel")]
    ]

    window = sg.Window("Decentralized Network", layout)
    while True:
        event, values = window.read()
        if event in (None, 'Cancel'):
            # User closed the Window or hit the Cancel button
            break
        choice = values['__CHOICE__']
        try:
            choice = int(choice)
        except:
            sg.Popup("Error Choice!")
            continue
        if choice == 1:
            regiser()
        elif choice == 2:
            post()
        elif choice == 3:
            get_messages()
        else:
            sg.Popup("Error Choice!")
    window.close()

def run():
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    t=threading.Thread(target=run)
    t.start()
    q=threading.Thread(target=run_mine)
    q.start()
    w=threading.Thread(target=client)
    w.start()
    event.set()