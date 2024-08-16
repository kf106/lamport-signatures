const crypto = require('crypto')

// create set A and set B
const A = new Array(256)
const B = new Array(256)

for (let i = 0; i < 256; i++) {
  A[i] = crypto.randomBytes(32)
  B[i] = crypto.randomBytes(32)
}

// create sets of hashes from A and B
const hashA = new Array(256)
const hashB = new Array(256)

for (let i = 0; i < 256; i++) {
  hashA[i] = crypto.createHash('sha256').update(A[i]).digest()
  hashB[i] = crypto.createHash('sha256').update(B[i]).digest()
}

// generate a hash of the message to sign
const message = 'this is my transaction'
const messageHash = crypto.createHash('sha256').update(message).digest()

function isBitSet (buf, bitIndex) {
  const byte = buf[~~(bitIndex / 8)]
  const bit = bitIndex % 8
  return !!(bit === 1 ? byte & 1 : byte & Math.pow(2, bit))
}

// generate signature by selecting A[i] or B[i] for each ith bit of
// messageHash: A[i] is selected if messageHash[i] = 0, and B[i] if it is 1
const Sig = new Array(256)

for (let i = 0; i < 256; i++) {
  isBitSet(messageHash, i) === true
    ? Sig[i] = A[i]
    : Sig[i] = B[i]
}

// Sig is the signature of message using the Lamport key [A, B]

// Let's check it

console.log("The message signed is: '" + message + "'")

const checkMessageHash = crypto.createHash('sha256').update(message).digest()
let checkResult = -1

for (let i = 0; i < 256; i++) {
  // we select which hash in the public key to check based on each bit of
  // the message hash
  const key = (isBitSet(checkMessageHash, i) === true ? hashA[i] : hashB[i])
  if (!(crypto.createHash('sha256').update(Sig[i]).digest().equals(key))) {
    checkResult = i
  }
}

if (checkResult === -1) {
  console.log('The signature is valid')
} else {
  console.log('The signature is invalid at entry ' + i.toString())
}

console.log("Now we tamper with the signature by changing the last element")
Sig[255] = crypto.randomBytes(32)

checkResult = -1

for (let i = 0; i < 256; i++) {
  // we select which hash in the public key to check based on each bit of
  // the message hash
  const key = (isBitSet(checkMessageHash, i) === true ? hashA[i] : hashB[i])
  if (!(crypto.createHash('sha256').update(Sig[i]).digest().equals(key))) {
    checkResult = i
  }
}

if (checkResult === -1) {
  console.log('The signature is valid')
} else {
  console.log('The signature is invalid at entry ' + checkResult.toString())
}



