import os
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import json
from tqdm import tqdm
from collections import Counter as count

getCipher = lambda key, iv: AES.new(key[:32].encode().zfill(32), AES.MODE_CBC, iv=iv[:16].encode().zfill(16))
# encrypt = lambda data, cipher: b64encode(cipher.encrypt(pad(data, 16)))
encrypt = lambda data, cipher: cipher.encrypt(pad(data, 16))
# decrypt = lambda data, cipher: unpad(cipher.decrypt(b64decode(data)), 16)
decrypt = lambda data, cipher: unpad(cipher.decrypt(data), 16)

def bigDataRead(obj, buffer: int):
    while True:
        data = obj.read(buffer)
        if not data: break
        yield(data)

def fileData(inFile, sliceSize: int):
    outFile, ext = os.path.splitext(inFile)
    return {'slices': bigDataRead(open(inFile, 'rb'), sliceSize), 'size': os.path.getsize(inFile), 'ext': ext, 'outFile': outFile}

def encryptFile(inFile: str, key: str, iv: str=''.zfill(16), sliceSize: int=2**17):
    fileData_ = fileData(inFile, sliceSize)
    size = fileData_['size']
    ext = fileData_['ext']
    outFile = fileData_['outFile']
    cipherСonfig = getCipher(key, iv)
    if os.path.exists(outFile): os.remove(outFile)
    with open(outFile, 'ab+') as of:
        with tqdm(range(size), f'encrypting [{os.path.split(inFile)[-1]}]', unit='B', unit_scale=True, unit_divisor=1024) as pbar:
            slicesSize = []
            checksumObj = hashlib.sha512()
            for slice in fileData_['slices']:
                checksumObj.update(slice)
                data = encrypt(slice, cipherСonfig)
                slicesSize.append(len(data))
                of.write(data)
                pbar.update(len(slice))
        try: dataSize, lastSliceSize = [obj for obj, count_ in count(slicesSize).most_common()]
        except ValueError: dataSize = lastSliceSize = len(data)
        config_ = json.dumps({
            'sliceSize': dataSize, 
            'lastSliceSize': lastSliceSize, 
            'ext': ext, 
            'checksum': checksumObj.hexdigest()
        })
        of.write(config_.encode('ascii'))
        of.write((len(config_)).to_bytes(10, byteorder='little'))

def decryptBytes(inFile: str, key: str, iv: str=''.zfill(16)):
    if not os.path.exists(inFile): return None
    size = os.path.getsize(inFile)
    with open(inFile, 'rb') as ifl:
        ifl.seek(-10, 2)
        zeros = int.from_bytes(ifl.read(), byteorder='little')
        ifl.seek(-1 * zeros - 10, 2)
        fileСonfig = json.loads(ifl.read(zeros).decode('ascii'))
        sliceSize = fileСonfig['sliceSize']
    try: cipherСonfig = getCipher(key, iv)
    except: return None
    slices = bigDataRead(open(inFile, 'rb'), sliceSize)
    with tqdm(range(size), f'decrypting [{os.path.split(inFile)[-1]}]', unit='B', unit_scale=True, unit_divisor=1024) as pbar:
        checksumObj = hashlib.sha512()
        for slice in slices:
            if len(slice) != sliceSize: slice = slice[:fileСonfig['lastSliceSize']]
            try: decryptData = decrypt(slice, cipherСonfig)
            except: return None
            checksumObj.update(decryptData)
            yield {'decryptData': decryptData, 'checksumObj': checksumObj, 'ext': fileСonfig['ext'], 'checksum': fileСonfig['checksum']}
            pbar.update(len(slice))

def decryptFile(inFile: str, outFile: str, key: str, iv: str=''.zfill(16)):
    if os.path.exists(outFile): os.remove(outFile)
    checksum = None
    with open(outFile, 'ab+') as of: 
        for _ in decryptBytes(inFile, key, iv):
            of.write(_['decryptData'])
            checksum = _['checksumObj'].hexdigest() == _['checksum']
    if not checksum: os.remove(outFile)        
    try: os.rename(outFile, f"{os.path.splitext(outFile)[0]}{_['ext']}")
    except: pass

encryptFile('1.png', 'hello')
decryptFile('1', '2', 'hello0')