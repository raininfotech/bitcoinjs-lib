import * as assert from 'assert';
import * as bip32 from 'bip32';
import { describe, it } from 'mocha';
import * as bitcoin from '../..';
import { regtestUtils } from './_regtest';
const rng = require('randombytes');
const regtest = regtestUtils.network;


const GUAPCOIN = {
  messagePrefix: '\x18Guapcoin Signed Message:\n',
  bech32: 'bc',
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 0x26,
  scriptHash: 0x06,
  wif: 0x2E,
};
// See bottom of file for some helper functions used to make the payment objects needed.

describe('bitcoinjs-lib (transactions with psbt)', () => {
  it('can create a 1-to-1 Transaction', () => {
    const alice = bitcoin.ECPair.fromWIF(
      'L2uPYXe17xSTqbCjZvL2DsyXPCbXspvcu5mHLDYUgzdUbZGSKrSr',
    );
    const psbt = new bitcoin.Psbt();
    psbt.setVersion(2); // These are defaults. This line is not needed.
    psbt.setLocktime(0); // These are defaults. This line is not needed.
    psbt.addInput({
      // if hash is string, txid, if hash is Buffer, is reversed compared to txid
      hash: '7d067b4a697a09d2c3cff7d4d9506c9955e93bff41bf82d439da7d030382bc3e',
      index: 0,
      sequence: 0xffffffff, // These are defaults. This line is not needed.

      // non-segwit inputs now require passing the whole previous tx as Buffer
      nonWitnessUtxo: Buffer.from(
        '0200000001f9f34e95b9d5c8abcd20fc5bd4a825d1517be62f0f775e5f36da944d9' +
        '452e550000000006b483045022100c86e9a111afc90f64b4904bd609e9eaed80d48' +
        'ca17c162b1aca0a788ac3526f002207bb79b60d4fc6526329bf18a77135dc566020' +
        '9e761da46e1c2f1152ec013215801210211755115eabf846720f5cb18f248666fec' +
        '631e5e1e66009ce3710ceea5b1ad13ffffffff01' +
        // value in satoshis (Int64LE) = 0x015f90 = 90000
        '905f010000000000' +
        // scriptPubkey length
        '19' +
        // scriptPubkey
        '76a9148bbc95d2709c71607c60ee3f097c1217482f518d88ac' +
        // locktime
        '00000000',
        'hex',
      ),

      // // If this input was segwit, instead of nonWitnessUtxo, you would add
      // // a witnessUtxo as follows. The scriptPubkey and the value only are needed.
      // witnessUtxo: {
      //   script: Buffer.from(
      //     '76a9148bbc95d2709c71607c60ee3f097c1217482f518d88ac',
      //     'hex',
      //   ),
      //   value: 90000,
      // },

      // Not featured here:
      //   redeemScript. A Buffer of the redeemScript for P2SH
      //   witnessScript. A Buffer of the witnessScript for P2WSH
    });
    psbt.addOutput({
      address: '1KRMKfeZcmosxALVYESdPNez1AP1mEtywp',
      value: 80000,
    });
    psbt.signInput(0, alice);
    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    assert.strictEqual(
      psbt.extractTransaction().toHex(),
      '02000000013ebc8203037dda39d482bf41ff3be955996c50d9d4f7cfc3d2097a694a7' +
      'b067d000000006b483045022100931b6db94aed25d5486884d83fc37160f37f3368c0' +
      'd7f48c757112abefec983802205fda64cff98c849577026eb2ce916a50ea70626a766' +
      '9f8596dd89b720a26b4d501210365db9da3f8a260078a7e8f8b708a1161468fb2323f' +
      'fda5ec16b261ec1056f455ffffffff0180380100000000001976a914ca0d36044e0dc' +
      '08a22724efa6f6a07b0ec4c79aa88ac00000000',
    );
  });

  it('can create (and broadcast via 3PBP) a typical Transaction', async () => {
    // these are { payment: Payment; keys: ECPair[] }
    const alice1 = createPayment('p2pkh');
    const alice2 = createPayment('p2pkh');

    // give Alice 2 unspent outputs
    const inputData1 = await getInputData(
      5e4,
      alice1.payment,
      false,
      'noredeem',
    );
    const inputData2 = await getInputData(
      7e4,
      alice2.payment,
      false,
      'noredeem',
    );
    {
      const {
        hash, // string of txid or Buffer of tx hash. (txid and hash are reverse order)
        index, // the output index of the txo you are spending
        nonWitnessUtxo, // the full previous transaction as a Buffer
      } = inputData1;
      assert.deepStrictEqual({ hash, index, nonWitnessUtxo }, inputData1);
    }

    // network is only needed if you pass an address to addOutput
    // using script (Buffer of scriptPubkey) instead will avoid needed network.
    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData1) // alice1 unspent
      .addInput(inputData2) // alice2 unspent
      .addOutput({
        address: 'mwCwTceJvYV27KXBc3NJZys6CjsgsoeHmf',
        value: 8e4,
      }) // the actual "spend"
      .addOutput({
        address: alice2.payment.address, // OR script, which is a Buffer.
        value: 1e4,
      }); // Alice's change
    // (in)(5e4 + 7e4) - (out)(8e4 + 1e4) = (fee)3e4 = 30000, this is the miner fee

    // Let's show a new feature with PSBT.
    // We can have multiple signers sign in parrallel and combine them.
    // (this is not necessary, but a nice feature)

    // encode to send out to the signers
    const psbtBaseText = psbt.toBase64();

    // each signer imports
    const signer1 = bitcoin.Psbt.fromBase64(psbtBaseText);
    const signer2 = bitcoin.Psbt.fromBase64(psbtBaseText);

    // Alice signs each input with the respective private keys
    // signInput and signInputAsync are better
    // (They take the input index explicitly as the first arg)
    signer1.signAllInputs(alice1.keys[0]);
    signer2.signAllInputs(alice2.keys[0]);

    // If your signer object's sign method returns a promise, use the following
    // await signer2.signAllInputsAsync(alice2.keys[0])

    // encode to send back to combiner (signer 1 and 2 are not near each other)
    const s1text = signer1.toBase64();
    const s2text = signer2.toBase64();

    const final1 = bitcoin.Psbt.fromBase64(s1text);
    const final2 = bitcoin.Psbt.fromBase64(s2text);

    // final1.combine(final2) would give the exact same result
    psbt.combine(final1, final2);

    // Finalizer wants to check all signatures are valid before finalizing.
    // If the finalizer wants to check for specific pubkeys, the second arg
    // can be passed. See the first multisig example below.
    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(psbt.validateSignaturesOfInput(1), true);

    // This step it new. Since we separate the signing operation and
    // the creation of the scriptSig and witness stack, we are able to
    psbt.finalizeAllInputs();

    // build and broadcast our RegTest network
    await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    // to build and broadcast to the actual Bitcoin network, see https://github.com/bitcoinjs/bitcoinjs-lib/issues/839
  });

  it('can create (and broadcast via 3PBP) a Transaction with an OP_RETURN output', async () => {
    const alice1 = createPayment('p2pkh');
    const inputData1 = await getInputData(
      2e5,
      alice1.payment,
      false,
      'noredeem',
    );

    const data = Buffer.from('bitcoinjs-lib', 'utf8');
    const embed = bitcoin.payments.embed({ data: [data] });

    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData1)
      .addOutput({
        script: embed.output!,
        value: 1000,
      })
      .addOutput({
        address: regtestUtils.RANDOM_ADDRESS,
        value: 1e5,
      })
      .signInput(0, alice1.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    // build and broadcast to the RegTest network
    await regtestUtils.broadcast(psbt.extractTransaction().toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2SH(P2MS(2 of 4)) (multisig) input', async () => {
    const multisig = createPayment('p2sh-p2ms(2 of 4)');
    const inputData1 = await getInputData(2e4, multisig.payment, false, 'p2sh');
    {
      const {
        hash,
        index,
        nonWitnessUtxo,
        redeemScript, // NEW: P2SH needs to give redeemScript when adding an input.
      } = inputData1;
      assert.deepStrictEqual(
        { hash, index, nonWitnessUtxo, redeemScript },
        inputData1,
      );
    }

    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData1)
      .addOutput({
        address: regtestUtils.RANDOM_ADDRESS,
        value: 1e4,
      })
      .signInput(0, multisig.keys[0])
      .signInput(0, multisig.keys[2]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(
      psbt.validateSignaturesOfInput(0, multisig.keys[0].publicKey),
      true,
    );
    assert.throws(() => {
      psbt.validateSignaturesOfInput(0, multisig.keys[3].publicKey);
    }, new RegExp('No signatures for this pubkey'));
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());

    await regtestUtils.verify({
      txId: tx.getId(),
      address: regtestUtils.RANDOM_ADDRESS,
      vout: 0,
      value: 1e4,
    });
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2SH(P2WPKH) input', async () => {
    const p2sh = createPayment('p2sh-p2wpkh');
    const inputData = await getInputData(5e4, p2sh.payment, true, 'p2sh');
    const inputData2 = await getInputData(5e4, p2sh.payment, true, 'p2sh');
    {
      const {
        hash,
        index,
        witnessUtxo, // NEW: this is an object of the output being spent { script: Buffer; value: Satoshis; }
        redeemScript,
      } = inputData;
      assert.deepStrictEqual(
        { hash, index, witnessUtxo, redeemScript },
        inputData,
      );
    }
    const keyPair = p2sh.keys[0];
    const outputData = {
      script: p2sh.payment.output, // sending to myself for fun
      value: 2e4,
    };
    const outputData2 = {
      script: p2sh.payment.output, // sending to myself for fun
      value: 7e4,
    };

    const tx = new bitcoin.Psbt()
      .addInputs([inputData, inputData2])
      .addOutputs([outputData, outputData2])
      .signAllInputs(keyPair)
      .finalizeAllInputs()
      .extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());

    await regtestUtils.verify({
      txId: tx.getId(),
      address: p2sh.payment.address,
      vout: 0,
      value: 2e4,
    });
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2SH(P2WPKH) input with nonWitnessUtxo', async () => {
    // For learning purposes, ignore this test.
    // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
    const p2sh = createPayment('p2sh-p2wpkh');
    const inputData = await getInputData(5e4, p2sh.payment, false, 'p2sh');
    const inputData2 = await getInputData(5e4, p2sh.payment, false, 'p2sh');
    const keyPair = p2sh.keys[0];
    const outputData = {
      script: p2sh.payment.output,
      value: 2e4,
    };
    const outputData2 = {
      script: p2sh.payment.output,
      value: 7e4,
    };
    const tx = new bitcoin.Psbt()
      .addInputs([inputData, inputData2])
      .addOutputs([outputData, outputData2])
      .signAllInputs(keyPair)
      .finalizeAllInputs()
      .extractTransaction();
    await regtestUtils.broadcast(tx.toHex());
    await regtestUtils.verify({
      txId: tx.getId(),
      address: p2sh.payment.address,
      vout: 0,
      value: 2e4,
    });
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WPKH input', async () => {
    // the only thing that changes is you don't give a redeemscript for input data

    const p2wpkh = createPayment('p2wpkh');
    const inputData = await getInputData(5e4, p2wpkh.payment, true, 'noredeem');
    {
      const { hash, index, witnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, witnessUtxo }, inputData);
    }

    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutput({
        address: regtestUtils.RANDOM_ADDRESS,
        value: 2e4,
      })
      .signInput(0, p2wpkh.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());

    await regtestUtils.verify({
      txId: tx.getId(),
      address: regtestUtils.RANDOM_ADDRESS,
      vout: 0,
      value: 2e4,
    });
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WPKH input with nonWitnessUtxo', async () => {
    // For learning purposes, ignore this test.
    // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
    const p2wpkh = createPayment('p2wpkh');
    const inputData = await getInputData(
      5e4,
      p2wpkh.payment,
      false,
      'noredeem',
    );
    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutput({
        address: regtestUtils.RANDOM_ADDRESS,
        value: 2e4,
      })
      .signInput(0, p2wpkh.keys[0]);
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    await regtestUtils.broadcast(tx.toHex());
    await regtestUtils.verify({
      txId: tx.getId(),
      address: regtestUtils.RANDOM_ADDRESS,
      vout: 0,
      value: 2e4,
    });
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WSH(P2PK) input', async () => {
    const p2wsh = createPayment('p2wsh-p2pk');
    const inputData = await getInputData(5e4, p2wsh.payment, true, 'p2wsh');
    {
      const {
        hash,
        index,
        witnessUtxo,
        witnessScript, // NEW: A Buffer of the witnessScript
      } = inputData;
      assert.deepStrictEqual(
        { hash, index, witnessUtxo, witnessScript },
        inputData,
      );
    }

    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutput({
        address: regtestUtils.RANDOM_ADDRESS,
        value: 2e4,
      })
      .signInput(0, p2wsh.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());

    await regtestUtils.verify({
      txId: tx.getId(),
      address: regtestUtils.RANDOM_ADDRESS,
      vout: 0,
      value: 2e4,
    });
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WSH(P2PK) input with nonWitnessUtxo', async () => {
    // For learning purposes, ignore this test.
    // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
    const p2wsh = createPayment('p2wsh-p2pk');
    const inputData = await getInputData(5e4, p2wsh.payment, false, 'p2wsh');
    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutput({
        address: regtestUtils.RANDOM_ADDRESS,
        value: 2e4,
      })
      .signInput(0, p2wsh.keys[0]);
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    await regtestUtils.broadcast(tx.toHex());
    await regtestUtils.verify({
      txId: tx.getId(),
      address: regtestUtils.RANDOM_ADDRESS,
      vout: 0,
      value: 2e4,
    });
  });

  it(
    'can create (and broadcast via 3PBP) a Transaction, w/ a ' +
    'P2SH(P2WSH(P2MS(3 of 4))) (SegWit multisig) input',
    async () => {
      const p2sh = createPayment('p2sh-p2wsh-p2ms(3 of 4)');
      const inputData = await getInputData(
        5e4,
        p2sh.payment,
        true,
        'p2sh-p2wsh',
      );
      {
        const {
          hash,
          index,
          witnessUtxo,
          redeemScript,
          witnessScript,
        } = inputData;
        assert.deepStrictEqual(
          { hash, index, witnessUtxo, redeemScript, witnessScript },
          inputData,
        );
      }

      const psbt = new bitcoin.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutput({
          address: regtestUtils.RANDOM_ADDRESS,
          value: 2e4,
        })
        .signInput(0, p2sh.keys[0])
        .signInput(0, p2sh.keys[2])
        .signInput(0, p2sh.keys[3]);

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
      assert.strictEqual(
        psbt.validateSignaturesOfInput(0, p2sh.keys[3].publicKey),
        true,
      );
      assert.throws(() => {
        psbt.validateSignaturesOfInput(0, p2sh.keys[1].publicKey);
      }, new RegExp('No signatures for this pubkey'));
      psbt.finalizeAllInputs();

      const tx = psbt.extractTransaction();

      // build and broadcast to the Bitcoin RegTest network
      await regtestUtils.broadcast(tx.toHex());

      await regtestUtils.verify({
        txId: tx.getId(),
        address: regtestUtils.RANDOM_ADDRESS,
        vout: 0,
        value: 2e4,
      });
    },
  );

  it(
    'can create (and broadcast via 3PBP) a Transaction, w/ a ' +
    'P2SH(P2WSH(P2MS(3 of 4))) (SegWit multisig) input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2sh = createPayment('p2sh-p2wsh-p2ms(3 of 4)');
      const inputData = await getInputData(
        5e4,
        p2sh.payment,
        false,
        'p2sh-p2wsh',
      );
      const psbt = new bitcoin.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutput({
          address: regtestUtils.RANDOM_ADDRESS,
          value: 2e4,
        })
        .signInput(0, p2sh.keys[0])
        .signInput(0, p2sh.keys[2])
        .signInput(0, p2sh.keys[3]);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
      await regtestUtils.verify({
        txId: tx.getId(),
        address: regtestUtils.RANDOM_ADDRESS,
        vout: 0,
        value: 2e4,
      });
    },
  );

  it(
    'can create (and broadcast via 3PBP) a Transaction, w/ a ' +
    'P2SH(P2MS(2 of 2)) input with nonWitnessUtxo',
    async () => {
      const myKey = bitcoin.ECPair.makeRandom({ network: regtest });
      const myKeys = [
        myKey,
        bitcoin.ECPair.fromPrivateKey(myKey.privateKey!, { network: regtest }),
      ];
      const p2sh = createPayment('p2sh-p2ms(2 of 2)', myKeys);
      const inputData = await getInputData(5e4, p2sh.payment, false, 'p2sh');
      const psbt = new bitcoin.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutput({
          address: regtestUtils.RANDOM_ADDRESS,
          value: 2e4,
        })
        .signInput(0, p2sh.keys[0]);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
      await regtestUtils.verify({
        txId: tx.getId(),
        address: regtestUtils.RANDOM_ADDRESS,
        vout: 0,
        value: 2e4,
      });
    },
  );

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WPKH input using HD', async () => {
    const hdRoot = bip32.fromSeed(rng(64));
    const masterFingerprint = hdRoot.fingerprint;
    const path = "m/84'/0'/0'/0/0";
    const childNode = hdRoot.derivePath(path);
    const pubkey = childNode.publicKey;

    // This information should be added to your input via updateInput
    // You can add multiple bip32Derivation objects for multisig, but
    // each must have a unique pubkey.
    //
    // This is useful because as long as you store the masterFingerprint on
    // the PSBT Creator's server, you can have the PSBT Creator do the heavy
    // lifting with derivation from your m/84'/0'/0' xpub, (deriving only 0/0 )
    // and your signer just needs to pass in an HDSigner interface (ie. bip32 library)
    const updateData = {
      bip32Derivation: [
        {
          masterFingerprint,
          path,
          pubkey,
        },
      ],
    };
    const p2wpkh = createPayment('p2wpkh', [childNode]);
    const inputData = await getInputData(5e4, p2wpkh.payment, true, 'noredeem');
    {
      const { hash, index, witnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, witnessUtxo }, inputData);
    }

    // You can add extra attributes for updateData into the addInput(s) object(s)
    Object.assign(inputData, updateData);

    const psbt = new bitcoin.Psbt({ network: regtest })
      .addInput(inputData)
      // .updateInput(0, updateData) // if you didn't merge the bip32Derivation with inputData
      .addOutput({
        address: regtestUtils.RANDOM_ADDRESS,
        value: 2e4,
      })
      .signInputHD(0, hdRoot); // must sign with root!!!

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(
      psbt.validateSignaturesOfInput(0, childNode.publicKey),
      true,
    );
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());

    await regtestUtils.verify({
      txId: tx.getId(),
      address: regtestUtils.RANDOM_ADDRESS,
      vout: 0,
      value: 2e4,
    });
  });
});

function createPayment(_type: string, myKeys?: any[], network?: any): any {
  network = network || regtest;
  const splitType = _type.split('-').reverse();
  const isMultisig = splitType[0].slice(0, 4) === 'p2ms';
  const keys = myKeys || [];
  let m: number | undefined;
  if (isMultisig) {
    const match = splitType[0].match(/^p2ms\((\d+) of (\d+)\)$/);
    m = parseInt(match![1], 10);
    let n = parseInt(match![2], 10);
    if (keys.length > 0 && keys.length !== n) {
      throw new Error('Need n keys for multisig');
    }
    while (!myKeys && n > 1) {
      keys.push(bitcoin.ECPair.makeRandom({ network }));
      n--;
    }
  }
  if (!myKeys) keys.push(bitcoin.ECPair.makeRandom({ network }));

  let payment: any;
  splitType.forEach(type => {
    if (type.slice(0, 4) === 'p2ms') {
      payment = bitcoin.payments.p2ms({
        m,
        pubkeys: keys.map(key => key.publicKey).sort((a, b) => a.compare(b)),
        network,
      });
    } else if (['p2sh', 'p2wsh'].indexOf(type) > -1) {
      payment = (bitcoin.payments as any)[type]({
        redeem: payment,
        network,
      });
    } else {
      payment = (bitcoin.payments as any)[type]({
        pubkey: keys[0].publicKey,
        network,
      });
    }
  });

  return {
    payment,
    keys,
  };
}

function getWitnessUtxo(out: any): any {
  delete out.address;
  out.script = Buffer.from(out.script, 'hex');
  return out;
}

async function getInputData(
  amount: number,
  payment: any,
  isSegwit: boolean,
  redeemType: string,
): Promise<any> {
  const unspent = await regtestUtils.faucetComplex(payment.output, amount);
  const utx = await regtestUtils.fetch(unspent.txId);
  // for non segwit inputs, you must pass the full transaction buffer
  const nonWitnessUtxo = Buffer.from(utx.txHex, 'hex');
  // for segwit inputs, you only need the output script and value as an object.
  const witnessUtxo = getWitnessUtxo(utx.outs[unspent.vout]);
  const mixin = isSegwit ? { witnessUtxo } : { nonWitnessUtxo };
  const mixin2: any = {};
  switch (redeemType) {
    case 'p2sh':
      mixin2.redeemScript = payment.redeem.output;
      break;
    case 'p2wsh':
      mixin2.witnessScript = payment.redeem.output;
      break;
    case 'p2sh-p2wsh':
      mixin2.witnessScript = payment.redeem.redeem.output;
      mixin2.redeemScript = payment.redeem.output;
      break;
  }
  return {
    hash: unspent.txId,
    index: unspent.vout,
    ...mixin,
    ...mixin2,
  };
}

describe('bitcoinjs-lib (transactions with TransactionBuilder)', function () {
  it('can create a  1-to-1 Guapcoin Transaction', function () {

    //pass input address private key
    const alice = bitcoin.ECPair.fromWIF('L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy',GUAPCOIN)
    
    //pass coin network
    const txb = new bitcoin.TransactionBuilder(GUAPCOIN)
    txb.setVersion(1)
    txb.addInput('61d520ccb74288c96bc1a2b20ea1c0d5a704776dd0164a396efec3ea7040349d', 0) 
    // Alice's previous transaction output, has 15000 satoshis
    txb.addOutput('GbuWoFPgLQUWypdLip4jnEkMUWJVtbu4Hk', 12000)
    // (in)15000 - (out)12000 = (fee)3000, this is the miner fee

    txb.sign(0, alice)

    // prepare for broadcast to the Bitcoin network, see "can broadcast a Transaction" below
    assert.strictEqual(txb.build().toHex(), '01000000019d344070eac3fe6e394a16d06d7704a7d5c0a10eb2a2c16bc98842b7cc20d561000000006b48304502210088828c0bdfcdca68d8ae0caeb6ec62cd3fd5f9b2191848edae33feb533df35d302202e0beadd35e17e7f83a733f5277028a9b453d525553e3f5d2d7a7aa8010a81d60121029f50f51d63b345039a290c94bffd3180c99ed659ff6ea6b1242bca47eb93b59fffffffff01e02e0000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac00000000')
  })

  it('can create a Guapcoin 2-to-2 Transaction', function () {

    //pass input addresses private key
    const alice = bitcoin.ECPair.fromWIF('L1Knwj9W3qK3qMKdTvmg3VfzUs3ij2LETTFhxza9LfD5dngnoLG1',GUAPCOIN)
    const bob = bitcoin.ECPair.fromWIF('KwcN2pT3wnRAurhy7qMczzbkpY5nXMW2ubh696UBc1bcwctTx26z',GUAPCOIN)

    //pass coin network
    const txb = new bitcoin.TransactionBuilder(GUAPCOIN)
    txb.setVersion(1)
    txb.addInput('b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c', 6) 
    // Alice's previous transaction output, has 200000 satoshis
    txb.addInput('7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730', 0) 
    // Bob's previous transaction output, has 300000 satoshis
    txb.addOutput('GbuWoFPgLQUWypdLip4jnEkMUWJVtbu4Hk', 180000)
    txb.addOutput('GZ47wMFVassQ5Bg4oMuYzFX4e8hTUtanii', 170000)
    // (in)(200000 + 300000) - (out)(180000 + 170000) = (fee)150000, this is the miner fee

    txb.sign(1, bob) // Bob signs his input, which was the second input (1th)
    txb.sign(0, alice) // Alice signs her input, which was the first input (0th)

    // prepare for broadcast to the Bitcoin network, see "can broadcast a Transaction" below
    assert.strictEqual(txb.build().toHex(), '01000000024c94e48a870b85f41228d33cf25213dfcc8dd796e7211ed6b1f9a014809dbbb5060000006a473044022041450c258ce7cac7da97316bf2ea1ce66d88967c4df94f3e91f4c2a30f5d08cb02203674d516e6bb2b0afd084c3551614bd9cec3c2945231245e891b145f2d6951f0012103e05ce435e462ec503143305feb6c00e06a3ad52fbf939e85c65f3a765bb7baacffffffff3077d9de049574c3af9bc9c09a7c9db80f2d94caaf63988c9166249b955e867d000000006b483045022100aeb5f1332c79c446d3f906e4499b2e678500580a3f90329edf1ba502eec9402e022072c8b863f8c8d6c26f4c691ac9a6610aa4200edc697306648ee844cfbc089d7a012103df7940ee7cddd2f97763f67e1fb13488da3fbdd7f9c68ec5ef0864074745a289ffffffff0220bf0200000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac10980200000000001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac00000000')
  })

  it('can create a Guapcoin 1-to-2 Transaction', function () {
    //pass input address private key
    const alice = bitcoin.ECPair.fromWIF('L1Knwj9W3qK3qMKdTvmg3VfzUs3ij2LETTFhxza9LfD5dngnoLG1',GUAPCOIN)

    //pass coin network
    const txb = new bitcoin.TransactionBuilder(GUAPCOIN)
    txb.setVersion(1)
    txb.addInput('b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c', 6) 
    // Alice's previous transaction output, has 200000 satoshis
    txb.addOutput('GZ47wMFVassQ5Bg4oMuYzFX4e8hTUtanii', 180000)
    txb.addOutput('GbuWoFPgLQUWypdLip4jnEkMUWJVtbu4Hk', 170000)
    // (in)(200000 + 300000) - (out)(180000 + 170000) = (fee)150000, this is the miner fee

    txb.sign(0, alice) // Alice signs her input, which was the first input (0th)

    // prepare for broadcast to the Bitcoin network, see "can broadcast a Transaction" below
    assert.strictEqual(txb.build().toHex(), '01000000024c94e48a870b85f41228d33cf25213dfcc8dd796e7211ed6b1f9a014809dbbb5060000006a473044022041450c258ce7cac7da97316bf2ea1ce66d88967c4df94f3e91f4c2a30f5d08cb02203674d516e6bb2b0afd084c3551614bd9cec3c2945231245e891b145f2d6951f0012103e05ce435e462ec503143305feb6c00e06a3ad52fbf939e85c65f3a765bb7baacffffffff3077d9de049574c3af9bc9c09a7c9db80f2d94caaf63988c9166249b955e867d000000006b483045022100aeb5f1332c79c446d3f906e4499b2e678500580a3f90329edf1ba502eec9402e022072c8b863f8c8d6c26f4c691ac9a6610aa4200edc697306648ee844cfbc089d7a012103df7940ee7cddd2f97763f67e1fb13488da3fbdd7f9c68ec5ef0864074745a289ffffffff0220bf0200000000001976a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac10980200000000001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac00000000')
  })
});