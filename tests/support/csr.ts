// CSR оператора агента для тестов (РП65): PKCS#10 любой пары ключей — P-256 по шаблону и чужие (P-384, RSA, ed25519)
// для негативных случаев. Правильность сборки проверяет openssl req -verify (tests/unit/ca-openssl.test.ts).
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { bitString, oid, seq, set, tlv, uint, utf8 } from "../../src/registry/ca/der.js";

export interface CsrOptions {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  /** CN субъекта; субъект в сертификат не переносится. */
  readonly cn?: string;
  /** Подписать другим ключом — CSR без владения ключом. */
  readonly signWith?: KeyObject;
  /** OID алгоритма подписи; по умолчанию — по виду ключа. */
  readonly sigOid?: string;
  /** Субъект целиком (DER Name) вместо CN. */
  readonly subject?: Buffer;
  /** SubjectPublicKeyInfo целиком вместо ключа publicKey. */
  readonly spki?: Buffer;
}

const defaultSigOid = (key: KeyObject): string => {
  if (key.asymmetricKeyType === "ed25519") return "1.3.101.112";
  if (key.asymmetricKeyType === "rsa") return "1.2.840.113549.1.1.11";
  return "1.2.840.10045.4.3.2";
};

export function buildCsrDer(o: CsrOptions): Buffer {
  const signer = o.signWith ?? o.privateKey;
  const sigOid = o.sigOid ?? defaultSigOid(signer);
  const info = seq(
    uint(Buffer.from([0])),
    o.subject ?? seq(set(seq(oid("2.5.4.3"), utf8(o.cn ?? "agent")))),
    o.spki ?? o.publicKey.export({ format: "der", type: "spki" }),
    tlv(0xa0),
  );
  const alg = signer.asymmetricKeyType === "rsa" ? seq(oid(sigOid), tlv(0x05)) : seq(oid(sigOid));
  const digest = signer.asymmetricKeyType === "ed25519" ? null : "sha256";
  const signature = sign(digest, info, signer.asymmetricKeyType === "ec" ? { key: signer, dsaEncoding: "der" } : signer);
  return seq(info, alg, bitString(signature));
}

export const p256 = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });

/** CSR по шаблону РП65 в канонической base64 и его пара ключей. */
export function newCsr(cn?: string): { readonly csr: string; readonly publicKey: KeyObject; readonly privateKey: KeyObject } {
  const pair = p256();
  return { ...pair, csr: buildCsrDer({ ...pair, cn }).toString("base64") };
}
