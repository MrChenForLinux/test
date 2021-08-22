import json
import sys
from cose.algorithms import Es256
from cose.keys.curves import P256
from cose.algorithms import Es256, EdDSA, Ps256
from cose.headers import KID, Algorithm
from cose.keys import CoseKey
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve, RSAKpE, RSAKpN
from cose.keys.keyparam import KpKty
from cose.keys.keytype import KtyEC2, KtyRSA
from cose.messages import CoseMessage
from base45 import b45decode
import zlib
from base64 import b64decode, b64encode
import cbor2
import re
from datetime import date, datetime
from qrdecode import qrdecode

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError ("Type %s not serializable" % type(obj))

filename = sys.argv[1]
cin = qrdecode.decode(filename)
#cin = qrdecode.decode('D:\Projects\hc1_verify\photo1.jpg')
#cin = input()
cin = cin.encode("ASCII")
#cin = "NCFOXN%TSMAHN-HOUKYHFKK1C8JY%7GBH$3OAD61Y5:X9MPS2KL6R5TC5/09PV5-FJLF6EB9UM97H98$QP3R8999Q9E$BDZI69J5.SS735TS ZJ::AJZC /KG-K8.G BF2SV55L1W0$%PB.V Q5-L9BOA9I06YBTVK:OI4V2UZ4+FJE 4Y3LL/II 05B92V4X$75-C5-C:NNUE9.IP6MIVZ0K1HB*0VON62PL$0 +AC1LCY0EPRT*89I6*XK YQ *PT*O2 QT O33Q67NZ30SW6IA6PK95-0*F7PTM -O2DO/24BD79G8CU6O8QGU68ORJSPZHQKZ5LSPD1R4NPX8QG+P09RK75%UOXKRHOOSMTTSIUR60CPP$1MDUYQA.:R3AN%BT-3K4JAUZU4-TF JQ7INNVMCQJ4V-5T8EB.:3P0ITDRT-J89B+CFTOMUAUJXTYW577SNEUG24B50Y/PM0".encode("ASCII")
cin = cin.decode("ASCII")
if cin.startswith('HC1'):
    cin = cin[3:]
    if cin.startswith(':'):
        cin = cin[1:]
cin = b45decode(cin)
cin = zlib.decompress(cin)
decoded = CoseMessage.decode(cin)
#print(decoded)
#kid = b'y\x03\x98\xe8\x10\xe9\xfa\xf3'
given_kid = None
if KID in decoded.phdr.keys():
   given_kid = decoded.phdr[KID]
else:
   given_kid = decoded.uhdr[KID]
given_kid_b64 = b64encode(given_kid).decode('ASCII')
print(f"Signature           : {given_kid_b64} @ {decoded.phdr[Algorithm].fullname}")
#print(given_kid_b64)
print(f"Correct signature againt known key (kid={given_kid_b64})", file=sys.stderr)

payload = decoded.payload
#print(payload)
payload = cbor2.loads(payload)
claim_names = {1: "Issuer", 6: "Issued At", 4: "Experation time", -260: "Health claims"}
for k in payload:
    if k != -260:
        n = f'Claim {k} (unknown)'
        if k in claim_names:
            n = claim_names[k]
        print(f'{n:20}: {payload[k]}')
payload = payload[-260][1]
n = 'Health payload'
print(f'{n:20}:', end="")
if 'dob' in payload:
    payload['dob'] = re.sub(r'\d{1}','X',payload['dob'])
if 'nam' in payload:
    for k in payload['nam'].keys():
        payload['nam'][k] = payload['nam'][k].encode("ascii","replace").decode('ascii')
        payload['nam'][k] = re.sub(r'[A-Z]{1}','X',payload['nam'][k])
        payload['nam'][k] = re.sub(r'[a-z\?]{1}','x', payload['nam'][k])
    payload = json.dumps(payload,indent=4,sort_keys=True,default=json_serial,ensure_ascii=False)
    payload = re.sub('URN:UV?CI:01:(\w+):\w+','URN:UCI:01:\g<1>:......', payload, flags=re.IGNORECASE)
print(payload)
