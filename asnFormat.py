from Cryptodome.Util.number import inverse, GCD
from Cryptodome.Random.random import randint
from asn1 import Encoder, Decoder, Numbers
from pygost import gost34112012256


def parseSignFile(signedFile):
    parameters = []
    dataToParse = b''
    with open(signedFile, "rb") as plaintText:
        for line in plaintText:
            dataToParse += line
    file = Decoder()
    file.start(dataToParse)
    file.enter()
    file.enter()
    file.enter()
    file.read()
    file.read()
    file.enter()
    p = file.read()[1]
    file.leave()
    file.enter()
    r = file.read()[1]
    a = file.read()[1]
    b = file.read()[1]
    file.leave()
    file.leave()
    file.enter()
    w = file.read()[1]
    s = file.read()[1]
    file.leave()
    file.leave()
    file.enter()
    file.leave()
    file.leave()
    parameters.append(p)
    parameters.append(r)
    parameters.append(a)
    parameters.append(b)
    parameters.append(w)
    parameters.append(s)
    EllipticCurve()
    return parameters


def generateSignFile(E, P, q, r, s, Q, p, A, B):
    Qx, Qy = lift(Q[0]), lift(Q[1])
    file = Encoder()
    file.start()
    file.enter(Numbers.Sequence)
    file.enter(Numbers.Set)
    file.enter(Numbers.Sequence)
    file.write(b'\x80\x06\x02\x00', Numbers.OctetString)
    file.write(b'ElGamal. Variant 8. Signature', Numbers.UTF8String)
    file.enter(Numbers.Sequence)
    file.write(b, Numbers.Integer)
    file.leave()
    file.enter(Numbers.Sequence)
    file.write(p, Numbers.Integer)
    file.write(r, Numbers.Integer)
    file.write(a, Numbers.Integer)
    file.leave()
    file.leave()
    file.enter(Numbers.Sequence)
    file.write(w, Numbers.Integer)
    file.write(s, Numbers.Integer)
    file.leave()
    file.leave()
    file.enter(Numbers.Sequence)
    file.leave()
    file.leave()
    with open("signedFile.asn1", "wb") as signedData:
        signedData.write(file.output())
