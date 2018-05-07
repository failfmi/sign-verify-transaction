const CryptoJS = require('crypto-js');
const EC = require('elliptic').ec;
const secp256k1 = new EC('secp256k1');

function signData(data, privKey) {
    let keyPair = secp256k1.keyFromPrivate(privKey);
    let signature = keyPair.sign(data);

    return [signature.r.toString(16), signature.s.toString(16)];
}

function decompressPublicKey(pubKeyCompressed) {
    let pubKeyX = pubKeyCompressed.substring(0, 64);
    let pubKeyYOdd = parseInt(pubKeyCompressed.substring(64));
    let pubKeyPoint = secp256k1.curve.pointFromX(pubKeyX, pubKeyYOdd);

    return pubKeyPoint;
}

function verifySignature(data, publicKey, signature) {
    let pubKeyPoint = decompressPublicKey(publicKey);
    let keyPair = secp256k1.keyPair({pub: pubKeyPoint});
    let result = keyPair.verify(data, {r: signature[0], s: signature[1]});
    return result;
}

class Transaction {
    constructor(from, to, value, fee, dateCreated, senderPubKey) {
        this.from = from; // Sender address: 40 hex digits
        this.to = to; // Recipient address: 40 hex digits
        this.value = value; // Transfer value: integer
        this.fee = fee; // Mining fee: integer
        this.dateCreated = dateCreated;   // ISO-8601 string
        this.senderPubKey = senderPubKey; // 65 hex digits
    }

    calculateTransactionHash() {
        let transactionDataJSON = JSON.stringify(this);

        this.transactionHash = CryptoJS.SHA256(transactionDataJSON).toString();
    }

    sign(privateKey) {
        this.senderSignature = signData(this.transactionHash, privateKey);
    }

    verify() {
        return verifySignature(this.transactionHash, this.senderPubKey, this.senderSignature);
    }
}

let transaction = new Transaction(
    "c3293572dbe6ebc60de4a20ed0e21446cae66b17",
    "f51362b7351ef62253a227a77751ad9b2302f911",
    25000,
    10,
    "2018-02-10T17:53:48.972Z",
    "c74a8458cd7a7e48f4b7ae6f4ae9f56c5c88c0f03e7c59cb4132b9d9d1600bba1"
);

transaction.calculateTransactionHash();

transaction.sign("7e4670ae70c98d24f3662c172dc510a085578b9ccc717e6c2f4e547edd960a34");
console.log(transaction.senderSignature);

transaction.verify();