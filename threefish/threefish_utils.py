def readfile(filepath):
    with open(filepath, 'rb') as f:
        dataInBytes = f.read()
    return dataInBytes


def padding256(dataInBytes):
    out = bytearray(dataInBytes)
    padding = len(dataInBytes) % 32
    out += b'\x00' * padding
    return bytes(out)


def separate64(dataWithPadding):
    if len(dataWithPadding) % 8 != 0:
        return []
    out = [bytes(dataWithPadding[i:i+8]) for i in range(0, len(dataWithPadding), 8)]
    return out


# additional function for official realization
def merge256(listOfByteWords):
    if len(listOfByteWords) % 32 != 0:
        return []

    out = []
    for i in range(0, len(listOfByteWords), 4):
        b = bytearray()
        for j in range(4):
            b += listOfByteWords[i+j]
        out += [bytes(b)]
    return out


def little_endian64(listOfByteWords):
    return [int.from_bytes(listOfByteWords[i], 'little') for i in range(len(listOfByteWords))]
