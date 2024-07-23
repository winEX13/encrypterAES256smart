import os
import sys
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import hashlib
from tqdm import tqdm
from collections import Counter as count
import yaml
import pickle

with open('config.yaml') as f: config = yaml.load(f, Loader=yaml.FullLoader)

getCipher = lambda key, iv: AES.new(key[:32].encode().zfill(32), mode=getattr(AES, config['mode']), iv=iv[:16].encode().zfill(16))
encrypt = lambda data, cipher: cipher.encrypt(pad(data, 16))
decrypt = lambda data, cipher: unpad(cipher.decrypt(data), 16)

def bigDataRead(obj, buffer: int):
    while True:
        data = obj.read(buffer)
        if not data: break
        yield(data)

def fileData(inFile, sliceSize: int):
    outFile, ext = os.path.splitext(inFile)
    return {'slices': bigDataRead(open(inFile, 'rb'), sliceSize), 'size': os.path.getsize(inFile), 'ext': ext, 'outFile': outFile}

def encryptFile(inFile: str, key: str, iv: str=''.zfill(16), sliceSize: int=config['default-slice-size']):
    fileData_ = fileData(inFile, sliceSize)
    size = fileData_['size']
    ext = fileData_['ext']
    outFile = fileData_['outFile']
    cipherConfig = getCipher(key, iv)
    if os.path.exists(outFile): os.remove(outFile)
    with open(outFile, 'ab+') as of:
        with tqdm(range(size), f'encrypting [{os.path.split(inFile)[-1]}]', unit='B', unit_scale=True, unit_divisor=1024) as pbar:
            slicesSize = []
            checksumObj = getattr(hashlib, config['hash'])()
            for slice in fileData_['slices']:
                checksumObj.update(slice)
                data = encrypt(slice, cipherConfig)
                slicesSize.append(len(data))
                of.write(data)
                pbar.update(len(slice))
        try: dataSize, lastSliceSize = [obj for obj, count_ in count(slicesSize).most_common()]
        except ValueError: dataSize = len(data)
        config_ = pickle.dumps({
            'sliceSize': dataSize, 
            'ext': ext, 
            'checksum': checksumObj.hexdigest()
        }, protocol=pickle.HIGHEST_PROTOCOL)
        of.write(config_)
        of.write((len(config_)).to_bytes(10, byteorder='little'))

def decryptBytes(inFile: str, key: str, iv: str=''.zfill(16)):
    if not os.path.exists(inFile): return None
    size = os.path.getsize(inFile)
    with open(inFile, 'rb') as ifl:
        ifl.seek(-10, 2)
        zeros = int.from_bytes(ifl.read(), byteorder='little')
        ifl.seek(-1 * zeros - 10, 2)
        fileConfig = pickle.loads(ifl.read(zeros))
        sliceSize = fileConfig['sliceSize']
    try: cipherConfig = getCipher(key, iv)
    except: return None
    slices = bigDataRead(open(inFile, 'rb'), sliceSize)
    with tqdm(range(size), f'decrypting [{os.path.split(inFile)[-1]}]', unit='B', unit_scale=True, unit_divisor=1024) as pbar:
        checksumObj = getattr(hashlib, config['hash'])()
        for slice in slices:
            if len(slice) != sliceSize: slice = slice[:-1 * zeros - 10]
            try: decryptData = decrypt(slice, cipherConfig)
            except: return None
            checksumObj.update(decryptData)
            yield {'decryptData': decryptData, 'checksumObj': checksumObj, 'ext': fileConfig['ext'], 'checksum': fileConfig['checksum']}
            pbar.update(len(slice))

def decryptFile(inFile: str, outFile: str, key: str, iv: str=''.zfill(16)):
    if os.path.exists(outFile): os.remove(outFile)
    checksum = None
    with open(outFile, 'ab+') as of: 
        for _ in decryptBytes(inFile, key, iv):
            of.write(_['decryptData'])
            checksum = _['checksumObj'].hexdigest() == _['checksum']
    if not checksum: os.remove(outFile)        
    try: 
        new = f"{os.path.splitext(outFile)[0]}{_['ext']}"
        if os.path.exists(new): os.remove(new)
        os.rename(outFile, new)
    except: pass

if __name__ == '__main__': 
    params = sys.argv[1:]
    if not params: 
        print('wrong params')
        exit()
    if params[0] == 'encrypt': 
        try: encryptFile(*params[1:])
        except: print('wrong encrypt data')
    elif params[0] == 'decrypt': 
        try: decryptFile(*params[1:])
        except: print('wrong decrypt data')
    else: print('wrong mode')