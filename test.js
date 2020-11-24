"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.numberToBytes = exports.numberToHex = exports.hexToBytes = exports.bytesToHex = void 0;
const micro_should_1 = require("micro-should");
const assert_1 = __importDefault(require("assert"));
const _1 = require(".");
function bytesToHex(uint8a) {
    // pre-caching chars could speed this up 6x.
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += uint8a[i].toString(16).padStart(2, '0');
    }
    return hex;
}
exports.bytesToHex = bytesToHex;
function hexToBytes(hex) {
    if (hex.length & 1)
        hex = `0${hex}`;
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
    }
    return array;
}
exports.hexToBytes = hexToBytes;
function numberToHex(num, padToBytes = 0) {
    const hex = num.toString(16);
    const p1 = hex.length & 1 ? `0${hex}` : hex;
    return p1.padStart(padToBytes * 2, "0");
}
exports.numberToHex = numberToHex;
function numberToBytes(num) {
    return hexToBytes(numberToHex(num));
}
exports.numberToBytes = numberToBytes;
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
function big(item) {
    return BigInt(`0x${bytesToHex(item)}`);
}
let i = 0;
for (const vector of vectors) {
    i++;
    micro_should_1.should(`run vector ${i}`, () => {
        const [seed, expMaster, childIndex, expChild] = vector;
        const master = _1.deriveMaster(hexToBytes(seed));
        const child = _1.deriveChild(master, childIndex);
        assert_1.default.equal(big(master), BigInt(expMaster));
        assert_1.default.equal(big(child), BigInt(expChild));
    });
}
micro_should_1.should.run();
