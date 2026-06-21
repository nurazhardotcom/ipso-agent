(ns ipso.identity
  "Identity Layer for ipso-agent:
   - Keypair generation (secp256k1 WIF & Pubkey)
   - IPv6 Cryptographically Generated Address (CGA) derivation per RFC 3972
   - BRC-52 Identity Certificates
   - BRC-31 Mutual Handshake Protocol"
  (:require [cheshire.core :as json]
            [clojure.tools.logging :as log])
  (:import [java.security MessageDigest SecureRandom]
           [java.util HexFormat Arrays Base64 UUID]
           [org.bouncycastle.jce.provider BouncyCastleProvider]
           [org.bouncycastle.asn1.sec SECNamedCurves]
           [org.bouncycastle.crypto.params ECDomainParameters ECPrivateKeyParameters ECPublicKeyParameters]
           [org.bouncycastle.crypto.signers ECDSASigner]
           [org.bouncycastle.math.ec ECPoint]))

;; ── Bouncy Castle Initialization ──
(defonce ^:private bc-provider
  (let [p (java.security.Security/getProvider "BC")]
    (when-not p
      (java.security.Security/addProvider (BouncyCastleProvider.)))))

(def ^:private secp256k1 (.getCurve (SECNamedCurves/getByName "secp256k1")))
(def ^:private ec-domain (ECDomainParameters. secp256k1
                                              (.getG (SECNamedCurves/getByName "secp256k1"))
                                              (.getN (SECNamedCurves/getByName "secp256k1"))))

;; ── Base58 & Cryptography ──
(def ^:private base58-alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(defn bytes->base58
  [^bytes bytes]
  (let [num (BigInteger. 1 bytes)]
    (loop [n num
           res ""]
      (if (zero? n)
        (let [leading-zeros (count (take-while zero? bytes))
              ones (apply str (repeat leading-zeros "1"))]
          (str ones res))
        (let [rem (.mod n (BigInteger/valueOf 58))
              char (nth base58-alphabet (.intValue rem))]
          (recur (.divide n (BigInteger/valueOf 58)) (str char res)))))))

(defn- sha256d [^bytes b]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (.digest md (.digest md b))))

(defn bytes->base58-check
  [^bytes bytes]
  (let [checksum (Arrays/copyOfRange (sha256d bytes) 0 4)
        total (byte-array (+ (alength bytes) 4))]
    (System/arraycopy bytes 0 total 0 (alength bytes))
    (System/arraycopy checksum 0 total (alength bytes) 4)
    (bytes->base58 total)))

(defn- decode-base58
  [s]
  (let [alphabet-map (into {} (map-indexed (fn [idx char] [char (biginteger idx)]) base58-alphabet))
        num (reduce (fn [acc char]
                      (if-let [val (alphabet-map char)]
                        (.add (.multiply acc (biginteger 58)) val)
                        (throw (ex-info "Invalid Base58 character" {:char char}))))
                    (biginteger 0)
                    s)
        leading-ones (count (take-while #(= \1 %) s))
        bytes (.toByteArray num)
        strip-sign (if (and (> (alength bytes) 1) (zero? (aget bytes 0)))
                     (Arrays/copyOfRange bytes 1 (alength bytes))
                     bytes)
        result (byte-array (+ leading-ones (alength strip-sign)))]
    (System/arraycopy strip-sign 0 result leading-ones (alength strip-sign))
    result))

(defn decode-base58-check [s]
  (let [bytes (decode-base58 s)]
    (if (< (alength bytes) 5)
      (throw (ex-info "Invalid Base58Check string: too short" {:length (alength bytes)}))
      (let [data-len (- (alength bytes) 4)
            data (Arrays/copyOfRange bytes 0 data-len)
            checksum (Arrays/copyOfRange bytes data-len (alength bytes))
            expected-checksum (Arrays/copyOfRange (sha256d data) 0 4)]
        (if (Arrays/equals checksum expected-checksum)
          data
          (throw (ex-info "Invalid Base58Check checksum" {})))))))

(defn wif->private-key-bytes
  [wif]
  (let [decoded (decode-base58-check wif)
        len (alength decoded)]
    (if (or (= len 33) (= len 34))
      (Arrays/copyOfRange decoded 1 33)
      (throw (ex-info "Invalid WIF private key length" {:length len})))))

(defn private-key-bytes->wif
  [^bytes priv-bytes compressed?]
  (let [prefix (unchecked-byte 0x80)
        len (if compressed? 34 33)
        payload (byte-array len)]
    (aset-byte payload 0 prefix)
    (System/arraycopy priv-bytes 0 payload 1 32)
    (when compressed?
      (aset-byte payload 33 (byte 0x01)))
    (bytes->base58-check payload)))

(defn private-key-bytes->pubkey-bytes
  [^bytes priv-bytes compressed?]
  (let [priv-bi (BigInteger. 1 priv-bytes)
        point (.multiply (.getG ec-domain) priv-bi)]
    (.getEncoded point compressed?)))

(defn derive-identity
  "Derive a compressed public key hex string from a WIF private key."
  [wif]
  (let [priv-bytes (wif->private-key-bytes wif)
        pubkey-bytes (private-key-bytes->pubkey-bytes priv-bytes true)]
    (.formatHex (HexFormat/of) pubkey-bytes)))

(defn- ripemd160
  [^bytes bytes]
  (let [d (org.bouncycastle.crypto.digests.RIPEMD160Digest.)]
    (.update d bytes 0 (alength bytes))
    (let [out (byte-array 20)]
      (.doFinal d out 0)
      out)))

(defn- hash160
  [^bytes bytes]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (ripemd160 (.digest md bytes))))

(defn public-key->address
  "Derive a Bitcoin address (Base58Check P2PKH) from a hex-encoded public key."
  [pub-key-hex]
  (let [pub-bytes (.parseHex (HexFormat/of) pub-key-hex)
        addr-hash (hash160 pub-bytes)
        addr-payload (byte-array (inc (alength addr-hash)))]
    (aset-byte addr-payload 0 0)
    (System/arraycopy addr-hash 0 addr-payload 1 (alength addr-hash))
    (bytes->base58-check addr-payload)))

;; ── Keypair Generation ──

(defn generate-agent-keypair
  "Generates a new secp256k1 keypair for the agent.
   Returns a map with :wif (private key) and :pubkey (hex string)."
  []
  (let [generator (org.bouncycastle.crypto.generators.ECKeyPairGenerator.)
        gen-params (org.bouncycastle.crypto.params.ECKeyGenerationParameters.
                    ec-domain (SecureRandom.))
        _ (.init generator gen-params)
        key-pair (.generateKeyPair generator)
        priv-key ^ECPrivateKeyParameters (.getPrivate key-pair)
        pub-key ^ECPublicKeyParameters (.getPublic key-pair)
        priv-d (-> priv-key .getD .toByteArray)
        ;; Normalize to 32 bytes
        priv-bytes (byte-array 32)
        _ (if (< (alength priv-d) 32)
            (System/arraycopy priv-d 0 priv-bytes (- 32 (alength priv-d)) (alength priv-d))
            (System/arraycopy priv-d (- (alength priv-d) 32) priv-bytes 0 32))
        pub-point (.getQ pub-key)
        pub-bytes (.getEncoded pub-point true)
        wif (private-key-bytes->wif priv-bytes true)
        pub-hex (.formatHex (HexFormat/of) pub-bytes)]
    {:wif wif
     :pubkey pub-hex}))

;; ── IPv6 CGA Derivation (RFC 3972) ──

(defn derive-cga-ipv6
  "Derive an IPv6 Cryptographically Generated Address (CGA) from public key.
   Parameters:
     - pubkey-hex: compressed public key hex string
     - subnet-prefix: 8-byte array or hex string (default: link-local fe80::)
     - sec: security parameter (0-7, default: 0)
   Returns the IPv6 address as a formatted string."
  ([pubkey-hex] (derive-cga-ipv6 pubkey-hex "fe80000000000000" 0))
  ([pubkey-hex subnet-prefix-hex sec]
   (let [hex-fmt (HexFormat/of)
         pub-bytes (.parseHex hex-fmt pubkey-hex)
         subnet-bytes (.parseHex hex-fmt subnet-prefix-hex)
         ;; CGA Parameters construction:
         ;; modifier (16 bytes), subnet-prefix (8 bytes), collision-count (1 byte), public-key (var)
         modifier (byte-array 16) ; 16 bytes of zeroes
         collision-count (byte 0)
         cga-params (byte-array (+ 16 8 1 (alength pub-bytes)))
         _ (System/arraycopy modifier 0 cga-params 0 16)
         _ (System/arraycopy subnet-bytes 0 cga-params 16 8)
         _ (aset-byte cga-params 24 collision-count)
         _ (System/arraycopy pub-bytes 0 cga-params 25 (alength pub-bytes))
         
         ;; Hash using SHA-1 (as per RFC 3972 section 2)
         sha1 (MessageDigest/getInstance "SHA-1")
         hash1 (.digest sha1 cga-params)
         
         ;; Extract interface identifier (first 8 bytes of hash)
         interface-id (Arrays/copyOfRange hash1 0 8)
         
         ;; Modify interface-id:
         ;; 1. Set Sec parameter (first 3 bits)
         ;; 2. Clear u-bit (bit 6) and g-bit (bit 7)
         first-byte (aget interface-id 0)
         cleared-u-g (bit-and (bit-and first-byte 0xfd) 0xfe) ; clears universal/local and individual/group
         modified-byte (unchecked-byte (bit-or cleared-u-g (bit-shift-left sec 5)))
         _ (aset-byte interface-id 0 modified-byte)
         
         ;; Combine subnet prefix and interface id to form full 16-byte IPv6 address
         ipv6-bytes (byte-array 16)
         _ (System/arraycopy subnet-bytes 0 ipv6-bytes 0 8)
         _ (System/arraycopy interface-id 0 ipv6-bytes 8 8)
         
         ;; Format to standard IPv6 string representation
         formatted (clojure.string/join ":"
                                        (map (fn [i]
                                               (format "%02x%02x"
                                                       (aget ipv6-bytes (* 2 i))
                                                       (aget ipv6-bytes (inc (* 2 i)))))
                                             (range 8)))]
     formatted)))

;; ── BRC-52 Identity Certificates ──

(defn sign-data
  "Signs a SHA-256 hash of message using secp256k1 private key (WIF).
   Returns a hex-encoded DER signature."
  [^String message ^String wif]
  (let [priv-bytes (wif->private-key-bytes wif)
        priv-key-param (ECPrivateKeyParameters. (BigInteger. 1 priv-bytes) ec-domain)
        md (MessageDigest/getInstance "SHA-256")
        msg-hash (.digest md (.getBytes message "UTF-8"))
        signer (ECDSASigner.)
        _ (.init signer true priv-key-param)
        [r s] (.generateSignature signer msg-hash)
        der-sig (let [asn1-seq (org.bouncycastle.asn1.DERSequence.
                                (into-array org.bouncycastle.asn1.ASN1Encodable
                                            [(org.bouncycastle.asn1.ASN1Integer. r)
                                             (org.bouncycastle.asn1.ASN1Integer. s)]))]
                  (.getEncoded asn1-seq))]
    (.formatHex (HexFormat/of) der-sig)))

(defn verify-data-signature
  "Verifies a DER signature against a message and a compressed public key."
  [^String message ^String signature-hex ^String pubkey-hex]
  (try
    (let [pub-bytes (.parseHex (HexFormat/of) pubkey-hex)
          der-sig (.parseHex (HexFormat/of) signature-hex)
          md (MessageDigest/getInstance "SHA-256")
          msg-hash (.digest md (.getBytes message "UTF-8"))
          
          asn1-seq (org.bouncycastle.asn1.ASN1Sequence/getInstance der-sig)
          r (.getValue (org.bouncycastle.asn1.ASN1Integer/getInstance (.getObjectAt asn1-seq 0)))
          s (.getValue (org.bouncycastle.asn1.ASN1Integer/getInstance (.getObjectAt asn1-seq 1)))
          
          pub-point (.decodePoint secp256k1 pub-bytes)
          pub-key-param (ECPublicKeyParameters. pub-point ec-domain)
          verifier (ECDSASigner.)]
      (.init verifier false pub-key-param)
      (.verifySignature verifier msg-hash r s))
    (catch Exception e
      (log/warn "Signature verification exception:" (.getMessage e))
      false)))

(defn create-identity-certificate
  "Creates a signed BRC-52 Identity Certificate.
   Returns a map with agent information and signature."
  [name pubkey cga wif]
  (let [timestamp (System/currentTimeMillis)
        payload (str name "|" pubkey "|" cga "|" timestamp)
        sig (sign-data payload wif)]
    {:name name
     :pubkey pubkey
     :cga cga
     :timestamp timestamp
     :signature sig}))

(defn verify-identity-certificate
  "Verifies the BRC-52 identity certificate."
  [cert]
  (let [payload (str (:name cert) "|" (:pubkey cert) "|" (:cga cert) "|" (:timestamp cert))]
    (and (verify-data-signature payload (:signature cert) (:pubkey cert))
         (= (:cga cert) (derive-cga-ipv6 (:pubkey cert))))))

;; ── BRC-31 Mutual Handshake Protocol ──

(defn generate-handshake-challenge
  "Generates a random challenge (nonce) for mutual authentication."
  []
  (str (UUID/randomUUID)))

(defn create-handshake-response
  "Signs the client challenge and generates a server challenge."
  [client-challenge server-wif]
  (let [server-challenge (generate-handshake-challenge)
        response-payload (str client-challenge "|" server-challenge)
        signature (sign-data response-payload server-wif)]
    {:server-challenge server-challenge
     :signature signature}))

(defn verify-handshake-response
  "Verifies server's response to client's challenge.
   If verified, signs the server's challenge to complete handshake."
  [client-challenge response server-pubkey client-wif]
  (let [payload (str client-challenge "|" (:server-challenge response))
        valid-server? (verify-data-signature payload (:signature response) server-pubkey)]
    (if valid-server?
      (let [client-signature (sign-data (:server-challenge response) client-wif)]
        {:verified true
         :client-signature client-signature})
      {:verified false})))

(defn verify-handshake-completion
  "Final step: Server verifies client's signature over server's challenge."
  [server-challenge client-signature client-pubkey]
  (verify-data-signature server-challenge client-signature client-pubkey))
