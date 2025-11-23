from django.shortcuts import render
import os
import json
from web3 import Web3, HTTPProvider
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
import pickle
from hashlib import sha256
import difflib
import hashlib
from datetime import datetime
from django.http import HttpResponse
from pinatapy import PinataPy

# Create your views here.

# It is recommended to use environment variables for API keys
PINATA_API_KEY = "cd288403f3ae7e912cf9"
PINATA_SECRET_API_KEY = "412a0f6c537835d2eb4625f7d2a9e24f1abe337a6997372df0bbca783edd1da0"
pinata = PinataPy(PINATA_API_KEY, PINATA_SECRET_API_KEY)

def index(request):
    return render(request,'index.html')

def owner(request):
    return render(request,'owner/Login.html')

def owner_register(request):
    return render(request,'owner/Register.html')

def get_web3_and_contract():
    blockchain_address = 'http://127.0.0.1:7545'
    web3 = Web3(HTTPProvider(blockchain_address))

    accounts = web3.eth.accounts
    if not accounts:
        raise RuntimeError("No accounts available from provider. Check Ganache.")
    default_account = accounts[0]

    # Path to Truffle's build JSON
    truffle_build_path = os.path.join(
        os.path.dirname(__file__),   # current directory (MainApp)
        "..",                        # go up one
        "Eth_Blockchain", "build", "contracts", "SmartContract.json"
    )
    truffle_build_path = os.path.abspath(truffle_build_path)

    with open(truffle_build_path) as f:
        contract_json = json.load(f)
        contract_abi = contract_json["abi"]

        # get network id dynamically
        network_id = web3.net.version   # e.g. "5777"
        if network_id not in contract_json["networks"]:
            raise RuntimeError(f"Contract not deployed on network {network_id}")
        #deployed_contract_address = contract_json["networks"][network_id]["address"]

    deployed_contract_address="0xb5C7f028602356518E84EB5264c33bd849E21A78"
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
    return web3, contract, default_account


def saveDetails(data, type):
    web3, contract, acct = get_web3_and_contract()

    # Option A: Use an unlocked account on Ganache and send transact with from
    try:
        if type == "signup":
            tx_hash = contract.functions.setRegister(data).transact({'from': acct})
            # modern web3.py uses wait_for_transaction_receipt
            receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            return receipt
        if type == "filestatus":
            tx_hash = contract.functions.setFileStatus(data).transact({'from':acct})
            receipt = web3.eth.waitForTransactionReceipt(tx_hash)
            return receipt


    except TypeError:

        # Some web3 versions return tx_hash as a hex-string. Try sending differently.
        tx_hash = contract.functions.setRegister(data).transact({'from': acct})
        receipt = web3.eth.waitForTransactionReceipt(tx_hash)
        return receipt
    except Exception as e:
        # If provider doesn't have unlocked accounts (e.g., Infura), you'll need to build, sign, and send.
        raise


def readUserDetails(contract_type):
    web3, contract, acct = get_web3_and_contract()
    if contract_type == 'signup':
        entries = contract.functions.getRegister().call()
        return entries
    if contract_type == 'getFileStatus':
        entries = contract.functions.getFileStatus().call()
        return entries
    return []


def OregAction(request):
    n = request.POST.get('name', '').strip()
    e = request.POST.get('email', '').strip()  # email variable fixed
    m = request.POST.get('mobile', '').strip()
    u = request.POST.get('username', '').strip()
    p = request.POST.get('password', '').strip()

    # Basic sanity checks (you can expand)
    if not e or not u:
        return render(request, 'owner/Register.html', {'msg': 'Missing required fields'})

    # 1) Load existing entries once
    try:
        existing = readUserDetails('signup')  # returns list of tuples [(timestamp, data_str), ...]
    except Exception as exc:
        # problem connecting to node / ABI mismatch
        return render(request, 'owner/Register.html', {'msg': f'Blockchain error: {exc}'})

    # 2) Check for duplicate email
    email_exists = False
    for dd in existing:

        # dd is expected to be (timestamp, data_string)
        if len(dd) >= 2:
            parts = dd[1].split("#")
            # You created data as: name#email#mobile#username#password
            if len(parts) >= 2 and parts[1] == e:
                email_exists = True
                break

    if email_exists:
        return render(request, 'owner/Register.html', {'msg': 'Email id Already Exist...!!'})

    data = f"{n}#{e}#{m}#{u}#{p}"

    try:
        receipt = saveDetails(data, "signup")
    except Exception as exc:
        return render(request, 'owner/Register.html', {'msg': f'Failed to save on blockchain: {exc}'})

    # successful
    return render(request, 'owner/Register.html',
                  {'msg': 'Registration Successful...!!', 'tx': receipt.transactionHash.hex()})

def Owner_login(request):
    u = request.POST['username']
    p = request.POST['password']

    existing = readUserDetails('signup')
    status = False
    for dd in existing:
        if len(dd)>=2:
            data = dd[1].split("#")
            if data[3]==u and data[4]==p:
                request.session['email']=data[1]
                status =True
    if status:
        return render(request, 'owner/OwnerHome.html')
    else:
        return render(request, 'owner/Login.html', {'msg': 'Login Failed..!!'})

def owner_home(request):
    return render(request, 'owner/OwnerHome.html')

def upload_file(request):
    return render(request,'owner/upload_file.html')


def save_file_with_email(file_bytes, owner_email):

    """
    Deduplication + Upload file to Pinata + Store on-chain with owner's email.
    Returns dict with {status, cid, file_hash, tx, email}.
    """
    web3, contract, acct = get_web3_and_contract()

    # 1) Compute SHA-256 digest (raw 32 bytes for Solidity bytes32)
    sha256_digest = hashlib.sha256(file_bytes).digest()   # correct for bytes32
    file_hash_hex = "0x" + hashlib.sha256(file_bytes).hexdigest()  # for display/logging only
    file_size = len(file_bytes)

    # 2) Check for duplicate on-chain
    try:
        duplicate = contract.functions.isDuplicate(sha256_digest).call()
    except Exception as e:
        raise RuntimeError(f"Contract call isDuplicate failed: {e}")

    if duplicate:
        owner, cid, email, size, ts = contract.functions.getFile(sha256_digest).call()
        return {
            'status': 'duplicate',
            'cid': cid,
            'owner_email': email,
            'size': size,
            'file_hash': file_hash_hex,
            'tx': None
        }
    else:
        # 3) Upload to Pinata
        try:
            # Create a temporary file to upload to Pinata
            with open("temp_file", "wb") as f:
                f.write(file_bytes)
            result = pinata.pin_file_to_ipfs("temp_file")
            cid = result['IpfsHash']
            os.remove("temp_file")
            if not cid:
                raise RuntimeError("Pinata did not return a valid CID")
        except Exception as e:
            raise RuntimeError(f"Pinata upload failed: {e}")

        # 4) Store record on-chain
        try:
            tx_hash = contract.functions.addFile(sha256_digest, cid, owner_email, file_size).transact({'from': acct})
            receipt = web3.eth.waitForTransactionReceipt(tx_hash)
        except Exception as e:
            raise RuntimeError(f"Failed to store file metadata on-chain: {e}")

        return {
            'status': 'stored',
            'cid': cid,
            'owner_email': owner_email,
            'file_hash': file_hash_hex,
            'size': file_size,
            'tx': receipt.transactionHash.hex()
        }


def read_file_details(file_bytes):
    """
    Look up file by hash, without uploading again.
    """
    web3, contract, acct = get_web3_and_contract()
    sha256_digest = hashlib.sha256(file_bytes).digest()
    file_hash_hex = "0x" + hashlib.sha256(file_bytes).hexdigest()

    try:
        ipfsCid, email, size, ts = contract.functions.getFile(sha256_digest).call()
        if ipfsCid == "":
            return None
        return {
            'cid': ipfsCid,
            'owner_email': email,
            'size': size,
            'timestamp': ts,
            'file_hash': file_hash_hex
        }
    except Exception as e:
        raise RuntimeError(f"Contract call getFile failed: {e}")

def upload_file_Action(request):
    owner_email = request.session['email']
    uploaded_file = request.FILES.get("file", None)


    if not uploaded_file or not owner_email:
        return render(request, "owner/upload_file.html", {"msg": "File and email required."})

    file_bytes = uploaded_file.read()
    try:
        result = save_file_with_email(file_bytes, owner_email)
    except Exception as e:
        return render(request, "owner/upload_file.html", {"msg": f"Error: {e}"})
    msg=""
    if result["status"]=='duplicate':
        msg= "This file already exists in the system ⚠️"
    else:
        msg = "File uploaded & stored successfully ✅"

    data = f"{msg}#{result['status']}#{result['cid']}#{result['owner_email']}#{result['file_hash']}#{result['size']}#{result['tx']}"
    try:
        receipt = saveDetails(data, "filestatus")
        print(receipt)
    except Exception as exc:
        return render(request, 'owner/upload_file.html', {'msg': f'Failed to save on blockchain: {exc}'})
    context = {
        "msg": msg,
        "status": result["status"],
        "cid": result["cid"],
        "owner_email": result["owner_email"],
        "file_hash": result["file_hash"],
        "size": result["size"],
        "tx": result["tx"],
    }
    return render(request, "owner/upload_file.html", context)



def get_files_by_owner(email: str):
    web3, contract, acct = get_web3_and_contract()
    normalized_email = email.strip().lower()

    try:
        result = contract.functions.getFilesByOwner(normalized_email).call()
    except Exception as e:
        raise RuntimeError(f"Contract call failed: {e}")

    if not result:
        return []

    parsed = []
    for f in result:
        # f[5] is the Unix timestamp from Solidity
        ts = datetime.fromtimestamp(f[5]).strftime("%Y-%m-%d %H:%M:%S")
        parsed.append({
            "owner": f[0],
            "cid": f[1],
            "file_hash": f[2].hex(),
            "owner_email": f[3],
            "size": f[4],
            "timestamp": ts,   # formatted string
        })
    return parsed

def view_files(request):
    email  = request.session['email']
    if not email:
        return render(request, "owner/view_files.html", {"msg": "Email required"})

    try:
        files = get_files_by_owner(email)
    except Exception as e:
        return render(request, "owner/view_files.html", {"msg": f"Error: {e}"})

    context = {"email": email, "files": files}
    return render(request, "owner/view_files.html", context)


#blockchain module operations

def blockchain(request):
    return render(request,'blockchain/Login.html')

def Blockchain_login(request):
    u = request.POST['username']
    p = request.POST['password']

    if u=='Blockchain' and p =='Blockchain':
        return render(request, 'blockchain/Home.html')
    else:
        return render(request, 'blockchain/Login.html',{'msg':'Login Failed...!!'})

def blockchain_home(request):
    return render(request, 'blockchain/Home.html')

def view_fileDetails(request):

    file_details = readUserDetails("getFileStatus")

    result_table = []

    for f in file_details:
        s = f[1].split("#")
        result_table.append({
            "msg":s[0],
            "status":s[1],
            "cid":s[2],
            "email":s[3],
            "hash":s[4],
            "size":s[5],
            "tx":s[6]
        })

    return render(request,'blockchain/view_fileDetails.html',{"result_table":result_table})

def ipfs(request):
    return render(request, 'ipfs/CloudLogin.html')

def ipfs_logAction(request):
    if request.method == "POST":
        try:
           # Check if Pinata is reachable
           pinata.pin_list()
        except Exception:
            return render(request, "ipfs/CloudLogin.html", {'msg':"⚠️ Pinata not reachable. Please check your connection and API keys."})
        u = request.POST.get("username")
        p = request.POST.get("password")

        if u == "IPFS" and p == "IPFS":
            return render(request, "ipfs/Home.html")
        else:
            return render(request, "ipfs/CloudLogin.html",{'msg':"❌ Invalid username or password"})

    return render(request, "ipfs/CloudLogin.html")

def ipfs_home(request):
    return render(request, "ipfs/Home.html")


def view_IPFSfileDetails(request):
    file_details = readUserDetails("getFileStatus")

    result_table = []

    for f in file_details:
        s = f[1].split("#")
        result_table.append({
            "msg": s[0],
            "status": s[1],
            "cid": s[2],
            "email": s[3],
            "hash": s[4],
            "size": s[5],
            "tx": s[6]
        })

    return render(request, 'ipfs/view_fileDetails.html', {"result_table": result_table})