import { inspect } from "node:util";
import assert from "node:assert";
import { DIGEST_LENGTH, digest } from "../lib/crypto.js";
import * as buffer from "node:buffer";
import test from "ava";
import { assertInstanceOf, merkleRoot, nibbles } from "../lib/helpers.js";
import { Leaf, Branch, Proof, Trie } from "../lib/trie.js";

const ACCOUNT_BALANCE_LIST = [
  {
    key: Buffer.from(
      "d8799f503450e8e7ff044148af0b0f151f490d99d8799f581c4ba6dd244255995969d2c05e323686bcbaba83b736e729941825d79bffd8799f581cec4574aacf96128597eff93ab9bc36c6bdc13d7f16ef5b62840ffa1fffff",
      "hex"
    ),
    value: Buffer.from("a0", "hex"),
  },
  {
    key: Buffer.from(
      "d8799f505bade4195c2e4136b9bca9b563725cadd8799f581cfdeb4bf0e8c077114a4553f1e05395e9fb7114db177f02f7b65c8de4ffd8799f581cfd92839136c47054fda09f2fbbb1792386a3b143cea5fca14fb8baceffff",
      "hex"
    ),
    value: Buffer.from(
      "a1581c5066154a102ee037390c5236f78db23239b49c5748d3d349f3ccf04ba14455534458192710",
      "hex"
    ),
  },
  {
    key: Buffer.from(
      "d8799f505bade4195c2e4136b9bca9b563725eeed8799f581c979a51682aec06f704ab144bbb50aded23d63790caa174b0e33aa545ffd8799f581ce8fbeb1a29c4a9aead8b68614f1f0fead352160f6a5d9925a7a89841ffff",
      "hex"
    ),
    value: Buffer.from("a140a1401864", "hex"),
  },
];

test("Trie.load", async (t) => {
  const trie = await Trie.fromList(ACCOUNT_BALANCE_LIST);
  const cbor = (await trie.toFullTreeCBOR()).toString("hex");
  t.is(
    cbor,
    "d8799f40a20ad8799f40a204d87a9f5820a4328cf4f7a8d99af2d6183e29a5ef5ddeb2a9c885e3a1938a2676b9abf897095f5840d8799f505bade4195c2e4136b9bca9b563725eeed8799f581c979a51682aec06f704ab144bbb50aded23d63790caa174b0e33aa545ffd8799f581ce8fbeb1a295819c4a9aead8b68614f1f0fead352160f6a5d9925a7a89841ffffff46a140a1401864ff08d87a9f5820a8bff8ba4c3d1226e11931acea10974faa5d4a36f6d3952af85c4a15c9ed909d5f5840d8799f505bade4195c2e4136b9bca9b563725cadd8799f581cfdeb4bf0e8c077114a4553f1e05395e9fb7114db177f02f7b65c8de4ffd8799f581cfd928391365819c47054fda09f2fbbb1792386a3b143cea5fca14fb8baceffffff5828a1581c5066154a102ee037390c5236f78db23239b49c5748d3d349f3ccf04ba14455534458192710ffff0fd87a9f5820f99beb2efeb35334b27c3ed37e4f5aa4ce89e57c07aa9f6c250fc2e2b59e71515f5840d8799f503450e8e7ff044148af0b0f151f490d99d8799f581c4ba6dd244255995969d2c05e323686bcbaba83b736e729941825d79bffd8799f581cec4574aacf581996128597eff93ab9bc36c6bdc13d7f16ef5b62840ffa1fffffff41a0ffff"
  );
});

function verifyRootHash(trie) {
  const { rootHash, prefix, node } = trie;

  function computeNodeHash(nodeData) {
    if (nodeData === null) {
      return null;
    }

    if (!nodeData.node) {
      // Leaf node
      const value =
        typeof nodeData.value === "string"
          ? Buffer.from(nodeData.value)
          : nodeData.value;
      assertInstanceOf(Buffer, { value });
      const leafHash = computeLeafHash(nodeData.suffix, digest(value));
      return leafHash;
    } else {
      // branch node
      const childHashes = Object.values(nodeData.node).map((child) => {
        if (child != null) {
          return computeNodeHash(child);
        } else {
          return null;
        }
      });
      const root = merkleRoot(childHashes);
      const branchHash = computeBranchHash(nodeData.prefix, root);
      return branchHash;
    }
  }

  const computedRootHash = computeNodeHash({ node, prefix });
  return computedRootHash.toString("hex") === rootHash;
}

function computeLeafHash(suffix, value) {
  // NOTE:
  // We append the remaining prefix to the value. However, to make this
  // step more efficient on-chain, we append it as a raw bytestring instead of
  // an array of nibbles.
  //
  // If the prefix's length is odd however, we must still prepend one nibble, and
  // then the rest.
  const isOdd = suffix.length % 2 > 0;

  const head = isOdd
    ? Buffer.concat([Buffer.from([0x00]), nibbles(suffix.slice(0, 1))])
    : Buffer.from([0xff]);

  const tail = Buffer.from(isOdd ? suffix.slice(1) : suffix, "hex");

  assert(
    value.length === DIGEST_LENGTH,
    `value must be a ${DIGEST_LENGTH}-byte digest but it is ${value?.toString(
      "hex"
    )}`
  );
  return digest(Buffer.concat([head, tail, value]));
}

function computeBranchHash(prefix, root) {
  assert(
    root.length === DIGEST_LENGTH,
    `root must be a ${DIGEST_LENGTH}-byte digest but it is ${root?.toString(
      "hex"
    )}`
  );

  return digest(Buffer.concat([nibbles(prefix), root]));
}
