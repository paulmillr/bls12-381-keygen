// @ts-ignore
import { strictEqual } from 'node:assert';
import { should } from 'micro-should';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { deriveMaster, deriveChild } from './index.js';
const vectors = [
    [
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        "6083874454709270928345386274498605044986640685124978867557563392430687146096",
        0,
        "20397789859736650942317412262472558107875392172444076792671091975210932703118",
    ],
    [
        "3141592653589793238462643383279502884197169399375105820974944592",
        "29757020647961307431480504535336562678282505419141012933316116377660817309383",
        3141592653,
        "25457201688850691947727629385191704516744796114925897962676248250929345014287",
    ],
    [
        "0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
        "27580842291869792442942448775674722299803720648445448686099262467207037398656",
        4294967295,
        "29358610794459428860402234341874281240803786294062035874021252734817515685787",
    ],
    [
        "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
        "19022158461524446591288038168518313374041767046816487870552872741050760015818",
        42,
        "31372231650479070279774297061823572166496564838472787488249775572789064611981",
    ],
];
function bytesToNumberBE(item) {
    return BigInt(`0x${bytesToHex(item)}`);
}
let i = 0;
for (const vector of vectors) {
    i++;
    should(`run vector ${i}`, () => {
        const [seed, expMaster, childIndex, expChild] = vector;
        const master = deriveMaster(hexToBytes(seed));
        const child = deriveChild(master, childIndex);
        strictEqual(bytesToNumberBE(master), BigInt(expMaster), 'master key is not equal');
        strictEqual(bytesToNumberBE(child), BigInt(expChild), 'child key is not equal');
    });
}
should.run();
