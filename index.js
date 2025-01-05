const express = require("express");
const fs = require("fs");
const cors = require("cors");
const bodyParser = require("body-parser");
// const Web3 = require("web3");
// const web3 = new Web3(new Web3.providers.HttpProvider("Geth Instance"));

const Web3 = require('web3');

// // any eth-rpc-url you own or have access to
const HTTP_PROVIDER = 'http://58.115.23.124:8545';
const web3 = new Web3(new Web3.providers.HttpProvider(HTTP_PROVIDER));

const compression = require("compression");

const { spawn } = require("child_process");
const graphene = require("graphene-pk11");
//var util = require('ethereumjs-util')
const keccak256 = require("js-sha3").keccak256;
const EthereumTx = require('ethereumjs-tx').Transaction;
const BigNumber = require("bignumber.js");
const util = require("ethereumjs-util");

// HSM Module Config
const Module = graphene.Module;
const lib = "/usr/local/lib/softhsm/libsofthsm2.so"; //linux
//var lib ="D:/SoftHSM2/lib/softhsm2-x64.dll" //windows
const mod = Module.load(lib, "SoftHSM");
mod.initialize();
const slot = mod.getSlots(0);
const session = slot.open(
  graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
);
session.login("1234");

//--------------------------------------------------------------
// Express server configuration
//--------------------------------------------------------------

const app = express();
app.use(cors());
app.use(bodyParser.json()); // to support JSON-encoded bodies
app.use(
  bodyParser.urlencoded({
    // to support URL-encoded bodies
    extended: true,
  })
);
app.use(express.static("./public"));

app.use(compression());

//--------------------------------------------------------------
// Main web pages
//--------------------------------------------------------------
app.get("/", (req, res) => res.sendFile(__dirname + "/default.html"));
app.get("/generate_keys.html", (req, res) =>
  res.sendFile(__dirname + "/generate_keys.html")
);
app.get("/tx_builder.html", (req, res) =>
  res.sendFile(__dirname + "/tx_builder.html")
);
app.get("/keyslist.html", (req, res) =>
  res.sendFile(__dirname + "/keyslist.html")
);

async function getLastTransactions(address, count) {
  let latestBlock = await web3.eth.getBlockNumber();
  let transactions = [];

  while (transactions.length < count && latestBlock >= 0) {
      const block = await web3.eth.getBlock(latestBlock, true); // Fetch full transactions
      block.transactions.forEach((tx) => {
          if (tx.from.toLowerCase() === address.toLowerCase() || 
              tx.to?.toLowerCase() === address.toLowerCase()) {
              transactions.push(tx);
          }
      });
      latestBlock--;
  }

  console.log(`Last ${count} transactions:`, transactions.slice(0, count));
}

// Get keys list
app.get("/api/keys/all", (req, res) => {
  EtherAddress = [];
  if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
    const keys = session.find({ class: graphene.ObjectClass.PUBLIC_KEY });
    for (i = 0; i < keys.length; i++) {
      try {
        puplicKey = decodeECPointToPublicKey(
          keys.items(i).getAttribute({ pointEC: null }).pointEC
        );
        pkstr = keys
          .items(i)
          .getAttribute({ keyGenMechanism: null }).keyGenMechanism;
          const address = util.keccak256(puplicKey); // keccak256 hash of publicKey
          const buf2 = Buffer.from(address, "hex");
          const EthAddr = "0x" + buf2.slice(-20).toString("hex"); // take lat 20 bytes as ethereum adress
          const label = keys.items(i).getAttribute({ label: null }).label;
        EtherAddress.push({ EthAddr, pkstr, label });
      } catch (e) {
        console.log(e)
      }
    }
    res.json(EtherAddress);
  }
});

app.post("/api/keys/generate", (req, res) => {
  const keylabel = req.body.keylabel;
  const ID = () => {
    return Math.random().toString(36).substr(2, 9);
  };
  // generate ECDSA key pair
  const gkeys = session.generateKeyPair(
    graphene.KeyGenMechanism.ECDSA,
    {
      label: keylabel,
      id: Buffer.from([ID]), // uniquer id for keys in storage https://www.cryptsoft.com/pkcs11doc/v230/group__SEC__9__7__KEY__OBJECTS.html
      keyType: graphene.KeyType.ECDSA,
      token: true,
      verify: true,
      paramsECDSA: graphene.NamedCurve.getByName("secp256k1").value,
    },
    {
      keyType: graphene.KeyType.ECDSA,
      label: keylabel,
      id: Buffer.from([ID]), // uniquer id for keys in storage https://www.cryptsoft.com/pkcs11doc/v230/group__SEC__9__7__KEY__OBJECTS.html
      token: true,
      sign: true,
    }
  );
  puplicKey = decodeECPointToPublicKey(
    gkeys.publicKey.getAttribute({ pointEC: null }).pointEC
  );
  const address = util.keccak256(puplicKey); // keccak256 hash of publicKey
  const buf2 = Buffer.from(address, "hex");
  const EthAddr = "0x" + buf2.slice(-20).toString("hex"); // take lat 20 bytes as ethereum adress
  pkstr = puplicKey.toString("hex");
  res.json({ EthAddr, pkstr });
});

app.get("/api/softhsm/specs", (req, res) => {
  slotLength = mod.getSlots().length;
  mechanisms = slot.getMechanisms();
  manufacturerID = slot.manufacturerID;
  slotDescription = slot.slotDescription;
  res.json({ slotLength, mechanisms, manufacturerID, slotDescription });
});

app.post("/api/keys/getpublickey", (req, res) => {
  ethereumAddress = req.body.ethereumAddress;
  if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
    const keys = session.find({ class: graphene.ObjectClass.PUBLIC_KEY });
    const pkstr = "Not Founded";
    for (i = 0; i < keys.length; i++) {
      try {
        puplicKey = decodeECPointToPublicKey(
          keys.items(i).getAttribute({ pointEC: null }).pointEC
        );
        const address = util.keccak256(puplicKey); // keccak256 hash of publicKey
        const buf2 = Buffer.from(address, "hex");
        const EthAddr = "0x" + buf2.slice(-20).toString("hex"); // take lat 20 bytes as ethereum adress
        console.log(keys.items(i).getAttribute({ label: null }).label);
        if (EthAddr == ethereumAddress) {
          pkstr = puplicKey.toString("hex");
          break;
        }
      } catch (e) {
        // console.log(e)
      }
    }
  }
  web3.eth.getTransactionCount(EthAddr).then((txCount) => {
    res.json({ pkstr, txCount });
  });
});

app.post("/api/tx/generator", (req, res) => {
  EthAddr = req.body.ethereumAddress;
  newNonce = req.body.newNonce;
  toAddr = req.body.toAddr.trim();
  value = req.body.value;
  let mID = '101564'; // ID from pkcs11-tool output
  //Get the Private key
  let hsmPvKeys = session.find({
    class: graphene.ObjectClass.PRIVATE_KEY,
    id: Buffer.from(mID, 'hex'),
  });
  // the HSM Private Key Instance (do not contain the private key value)
  let Pkeys = hsmPvKeys.items(0);
  //First sign : sign the ethreum address of the sender
  encoded_msg = EthAddr;

  // console.log last 10 transactions of EthAddr
  getLastTransactions(EthAddr, 10);


  let msgHash = util.keccak(encoded_msg); // msg to be signed is the generated ethereum address
  addressSign = calculateEthereumSig(msgHash, EthAddr, Pkeys);

  //using the r,s,v value from the first signautre in the transaction parameter
  const txParams = {
    nonce: web3.utils.toHex(newNonce),
    gasPrice: "0x0918400000",
    gasLimit: 160000,
    to: toAddr,
    value: web3.utils.toBN(value),
    data: "0x00",
    r: addressSign.r, // using r from the first signature
    s: addressSign.s, // using s from the first signature
    v: addressSign.v,
  };

  console.log(txParams);
  
  const customChain = {
    name: 'customchain1981',
    chainId: 1981,
    networkId: 1981,
    comment: 'My Custom Chain',
  };

  const tx = new EthereumTx(txParams, customChain);

  msgHash = tx.hash(false);


  //Second sign: sign the raw transactions
  const txSig = calculateEthereumSig(msgHash, EthAddr, Pkeys);
  tx.r = txSig.r;
  tx.s = txSig.s;
  tx.v = txSig.v;

  const serializedTx = tx.serialize().toString("hex");
  res.json({ serializedTx });
});

app.post("/api/tx/submit", (req, res) => {
  rawTx = req.body.rawtx;

  // Transaction ready for submission
  web3.eth
    .sendSignedTransaction("0x" + rawTx)
    .on("confirmation", function (confirmationNumber, receipt) {
      console.log(receipt);
      transactionHash = receipt.transactionHash;
      res.json({ transactionHash });
    })
    .on("error", console.error);
});

const decodeECPointToPublicKey = (data) => {
  if (data.length === 0 || data[0] !== 4) {
    throw new Error("Only uncompressed point format supported");
  }
  // Accoring to ASN encoded value, the first 3 bytes are
  //04 - OCTET STRING
  //41 - Length 65 bytes
  //For secp256k1 curve it's always 044104 at the beginning
  return data.slice(3, 67);
}

const calculateEthereumSig = (msgHash, EthreAddr, privateKey) => {
  ///////////////////////////////////////////////////////////////////////////////////////////////
  // Contiue Signing until find s < (secp256k1.size/2)
  ///////////////////////////////////////////////////////////////////////////////////////////////
  // Continue signing until find s < (secp256k1.size/2)
  let flag = true;
  let tempSig;

  // Not all EC signature is a valid signature
  while (flag) {
    
    const sign = session.createSign('ECDSA', privateKey);
    tempSig = sign.once(msgHash);
    const _s = tempSig.slice(32, 64);
    const sValue = new BigNumber(_s.toString('hex'), 16); // Hex
    const secp256k1N = new BigNumber(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
      16
    ); // Max value on the curve
    const secp256k1halfN = secp256k1N.div(new BigNumber(2));
    if (sValue.lt(secp256k1halfN)) {
      flag = false;
    }
  }

  const rs = {
    r: tempSig.slice(0, 32),
    s: tempSig.slice(32, 64),
  };
  let v = 27;
  let pubKey = util.ecrecover(util.toBuffer(msgHash), v, rs.r, rs.s);
  let addrBuf = util.pubToAddress(pubKey);
  let RecoveredEthAddr = util.bufferToHex(addrBuf);

  if (EthreAddr != RecoveredEthAddr) {
    v = 28;
    pubKey = util.ecrecover(util.toBuffer(msgHash), v, rs.r, rs.s);
    addrBuf = util.pubToAddress(pubKey);
    RecoveredEthAddr = util.bufferToHex(addrBuf);
  }
  return { r: rs.r, s: rs.s, v: v };
}

//------------------------------------------------------------------------
app.listen(8090, () =>
  console.log("Web app listening at http://localhost:8090")
);
